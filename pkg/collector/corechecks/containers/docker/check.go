// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build docker

// Package docker implements the docker check.
package docker

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/containers/generic"
	"github.com/DataDog/datadog-agent/pkg/metrics/event"
	"github.com/DataDog/datadog-agent/pkg/metrics/servicecheck"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-agent/pkg/util/hostname"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/option"
)

const (
	// CheckName is the name of the check
	CheckName = "docker"

	cacheValidity = 2 * time.Second
)

type eventTransformer interface {
	Transform([]*docker.ContainerEvent) ([]event.Event, []error)
}

type noopEventTransformer struct{}

func (noopEventTransformer) Transform([]*docker.ContainerEvent) ([]event.Event, []error) {
	return nil, nil
}

// DockerCheck grabs docker metrics
type DockerCheck struct {
	core.CheckBase
	instance                    *DockerConfig
	processor                   generic.Processor
	networkProcessorExtension   *dockerNetworkExtension
	dockerHostname              string
	containerFilter             *containers.Filter
	okExitCodes                 map[int]struct{}
	collectContainerSizeCounter uint64
	store                       workloadmeta.Component
	tagger                      tagger.Component

	lastEventTime    time.Time
	eventTransformer eventTransformer
}

// Factory returns a new docker corecheck factory
func Factory(store workloadmeta.Component, tagger tagger.Component) option.Option[func() check.Check] {
	return option.New(func() check.Check {
		return &DockerCheck{
			CheckBase: core.NewCheckBase(CheckName),
			instance:  &DockerConfig{},
			store:     store,
			tagger:    tagger,
		}
	})
}

var defaultFilteredEventTypes = []string{
	"top",
	"exec_create",
	"exec_start",
	"exec_die",
}

// Configure parses the check configuration and init the check
func (d *DockerCheck) Configure(senderManager sender.SenderManager, _ uint64, config, initConfig integration.Data, source string) error {
	err := d.CommonConfigure(senderManager, initConfig, config, source)
	if err != nil {
		return err
	}

	d.instance.Parse(config) //nolint:errcheck

	// Use the same hostname as the agent so that host tags (like `availability-zone:us-east-1b`)
	// are attached to Docker events from this host. The hostname from the docker api may be
	// different than the agent hostname depending on the environment (like EC2 or GCE).
	d.dockerHostname, err = hostname.Get(context.TODO())
	if err != nil {
		log.Warnf("Can't get hostname from docker, events will not have it: %v", err)
	}

	filteredEventTypes := d.instance.FilteredEventType
	if len(filteredEventTypes) == 0 {
		filteredEventTypes = defaultFilteredEventTypes
	}

	if d.instance.UnbundleEvents {
		var bundledTransformer eventTransformer = noopEventTransformer{}
		if d.instance.BundleUnspecifiedEvents {
			bundledTransformer = newBundledTransformer(
				d.dockerHostname,
				// Don't bundle events that are unbundled already.
				append(filteredEventTypes, d.instance.CollectedEventTypes...),
				d.tagger,
			)
		}
		d.eventTransformer = newUnbundledTransformer(d.dockerHostname, d.instance.CollectedEventTypes, bundledTransformer, d.tagger)
	} else {
		d.eventTransformer = newBundledTransformer(d.dockerHostname, filteredEventTypes, d.tagger)
	}

	d.containerFilter, err = containers.GetSharedMetricFilter()
	if err != nil {
		log.Warnf("Can't get container include/exclude filter, no filtering will be applied: %v", err)
	}

	d.processor = generic.NewProcessor(metrics.GetProvider(option.New(d.store)), generic.NewMetadataContainerAccessor(d.store), metricsAdapter{}, getProcessorFilter(d.containerFilter, d.store), d.tagger, false)
	d.processor.RegisterExtension("docker-custom-metrics", &dockerCustomMetricsExtension{})
	d.configureNetworkProcessor(&d.processor)
	d.setOkExitCodes()

	return nil
}

func (d *DockerCheck) getSender() (sender.Sender, error) {
	sender, err := d.GetSender()
	if err != nil {
		return sender, err
	}

	if len(d.instance.CappedMetrics) == 0 {
		// No cap set, using a bare sender
		return sender, nil
	}

	return generic.NewCappedSender(d.instance.CappedMetrics, sender), nil
}

// Run executes the check
func (d *DockerCheck) Run() error {
	sender, err := d.getSender()
	if err != nil {
		return err
	}

	du, err := docker.GetDockerUtil()
	if err != nil {
		sender.ServiceCheck(DockerServiceUp, servicecheck.ServiceCheckCritical, "", nil, err.Error())
		_ = d.Warnf("Error initialising check: %s", err)
		return err
	}

	collectContainerSize := false
	if d.instance.CollectContainerSize {
		collectContainerSize = d.collectContainerSizeCounter == 0
		d.collectContainerSizeCounter = (d.collectContainerSizeCounter + 1) % d.instance.CollectContainerSizeFreq
	}

	rawContainerList, err := du.RawContainerList(context.TODO(), container.ListOptions{All: true, Size: collectContainerSize})
	if err != nil {
		sender.ServiceCheck(DockerServiceUp, servicecheck.ServiceCheckCritical, "", nil, err.Error())
		_ = d.Warnf("Error collecting containers: %s", err)
		return err
	}

	if err := d.runProcessor(sender); err != nil {
		_ = d.Warnf("Error collecting metrics: %s", err)
	}

	return d.runDockerCustom(sender, du, rawContainerList)
}

func (d *DockerCheck) runProcessor(sender sender.Sender) error {
	return d.processor.Run(sender, cacheValidity)
}

// containersPerTags is a counter of running and stopped containers that share the same set of tags
type containersPerTags struct {
	tags    []string
	running int64
	stopped int64
}

func (d *DockerCheck) runDockerCustom(sender sender.Sender, du docker.Client, rawContainerList []container.Summary) error {
	// Container metrics
	var containersRunning, containersStopped uint64
	containerGroups := map[string]*containersPerTags{}

	// Network extension preRun hook
	if d.networkProcessorExtension != nil {
		d.networkProcessorExtension.preRun()
	}

	for _, rawContainer := range rawContainerList {
		if rawContainer.State == string(workloadmeta.ContainerStatusRunning) {
			containersRunning++
		} else {
			containersStopped++
		}

		// Network extension container hook
		if d.networkProcessorExtension != nil {
			d.networkProcessorExtension.processContainer(rawContainer)
		}

		// Resolve container image, if possible
		resolvedImageName, err := du.ResolveImageName(context.TODO(), rawContainer.ImageID)
		if err != nil {
			log.Debugf("Unable to resolve ImageID %q to an image name, will use %q: %s", rawContainer.ImageID, rawContainer.Image, err)
			resolvedImageName = rawContainer.Image
		}

		// We do reports some metrics about excluded containers, but the tagger won't have tags
		// We always use rawContainer.Names[0] to match historic behavior
		var containerName string
		if len(rawContainer.Names) > 0 {
			containerName = rawContainer.Names[0]
		}
		var annotations map[string]string
		if pod, err := d.store.GetKubernetesPodForContainer(rawContainer.ID); err == nil {
			annotations = pod.Annotations
		}

		isContainerExcluded := false
		if d.containerFilter != nil {
			isContainerExcluded = d.containerFilter.IsExcluded(annotations, containerName, resolvedImageName, rawContainer.Labels[kubernetes.CriContainerNamespaceLabel])
		}
		isContainerRunning := rawContainer.State == string(workloadmeta.ContainerStatusRunning)
		taggerEntityID := types.NewEntityID(types.ContainerID, rawContainer.ID)
		tags, err := d.getImageTagsFromContainer(taggerEntityID, resolvedImageName, isContainerExcluded || !isContainerRunning)
		if err != nil {
			log.Debugf("Unable to fetch tags for image: %s, err: %v", rawContainer.ImageID, err)
		} else {
			sort.Strings(tags)
			key := strings.Join(tags, "|")
			if _, found := containerGroups[key]; !found {
				containerGroups[key] = &containersPerTags{tags: tags, running: 0, stopped: 0}
			}

			if isContainerRunning {
				containerGroups[key].running++
			} else {
				containerGroups[key].stopped++
			}
		}

		// Metrics are only reported for running containers
		if isContainerExcluded || !isContainerRunning {
			continue
		}

		// Send container size metrics
		containerTags, err := d.tagger.Tag(taggerEntityID, types.HighCardinality)
		if err != nil {
			log.Warnf("Unable to fetch tags for container: %s, err: %v", rawContainer.ID, err)
		}

		if rawContainer.SizeRw > 0 || rawContainer.SizeRootFs > 0 {
			sender.Gauge("docker.container.size_rw", float64(rawContainer.SizeRw), "", containerTags)
			sender.Gauge("docker.container.size_rootfs", float64(rawContainer.SizeRootFs), "", containerTags)
		}
	}

	// Network extension postRun hook
	if d.networkProcessorExtension != nil {
		d.networkProcessorExtension.postRun()
	}

	// Image-Container metrics
	for _, group := range containerGroups {
		if group.running > 0 {
			sender.Gauge("docker.containers.running", float64(group.running), "", group.tags)
		}
		if group.stopped > 0 {
			sender.Gauge("docker.containers.stopped", float64(group.stopped), "", group.tags)
		}
	}
	sender.Gauge("docker.containers.running.total", float64(containersRunning), "", nil)
	sender.Gauge("docker.containers.stopped.total", float64(containersStopped), "", nil)

	// Image metrics
	if err := d.collectImageMetrics(sender, du); err != nil {
		return err
	}

	// Disk metrics
	d.collectDiskMetrics(sender, du)

	// Docker volumes metrics
	d.collectVolumeMetrics(sender, du)

	// All metrics collected, setting servicecheck to ok
	sender.ServiceCheck(DockerServiceUp, servicecheck.ServiceCheckOK, "", nil, "")

	// Collecting events
	d.collectEvents(sender, du)

	sender.Commit()
	return nil
}

func (d *DockerCheck) collectImageMetrics(sender sender.Sender, du docker.Client) error {
	availableImages, err := du.Images(context.TODO(), false)
	if err != nil {
		log.Warnf("Unable to list Docker images, err: %v", err)
		_ = d.Warnf("Unable to list Docker images, err: %v", err)
		sender.ServiceCheck(DockerServiceUp, servicecheck.ServiceCheckCritical, "", nil, err.Error())
		return err
	}
	allImages, err := du.Images(context.TODO(), true)
	if err != nil {
		log.Warnf("Unable to list Docker images, err: %v", err)
		_ = d.Warnf("Unable to list Docker images, err: %v", err)
		sender.ServiceCheck(DockerServiceUp, servicecheck.ServiceCheckCritical, "", nil, err.Error())
		return err
	}

	if d.instance.CollectImageSize {
		for _, image := range availableImages {
			imageName := du.GetPreferredImageName(image.ID, image.RepoTags, image.RepoDigests)
			imageTags, err := getImageTags(imageName)
			if err != nil {
				log.Tracef("Unable to resolve image from repotags/digests with id: %s, err: %v", imageName, err)
				continue
			}

			//nolint:staticcheck // TODO(CINT) Fix staticcheck linter
			sender.Gauge("docker.image.virtual_size", float64(image.VirtualSize), "", imageTags)
			sender.Gauge("docker.image.size", float64(image.Size), "", imageTags)
		}
	}
	sender.Gauge("docker.images.available", float64(len(availableImages)), "", nil)
	sender.Gauge("docker.images.intermediate", float64(len(allImages)-len(availableImages)), "", nil)
	return nil
}

func (d *DockerCheck) collectEvents(sender sender.Sender, du docker.Client) {
	if d.instance.CollectEvent || d.instance.CollectExitCodes {
		events, err := d.retrieveEvents(du)
		if err != nil {
			d.Warnf("Error collecting events: %s", err) //nolint:errcheck
			return
		}

		if d.instance.CollectEvent {
			err = d.reportEvents(events, sender)
			if err != nil {
				log.Warn(err.Error())
			}
		}

		if d.instance.CollectExitCodes {
			d.reportExitCodes(events, sender)
		}
	}
}

func (d *DockerCheck) collectDiskMetrics(sender sender.Sender, du docker.Client) {
	if d.instance.CollectDiskStats {
		stats, err := du.GetStorageStats(context.TODO())
		if err != nil {
			d.Warnf("Error collecting disk stats: %s", err) //nolint:errcheck
		} else {
			for _, stat := range stats {
				if stat.Name != docker.DataStorageName && stat.Name != docker.MetadataStorageName {
					log.Debugf("Ignoring unknown disk stats: %s", stat.Name)
					continue
				}
				if stat.Free != nil {
					sender.Gauge(fmt.Sprintf("docker.%s.free", stat.Name), float64(*stat.Free), "", nil)
				}
				if stat.Used != nil {
					sender.Gauge(fmt.Sprintf("docker.%s.used", stat.Name), float64(*stat.Used), "", nil)
				}
				if stat.Total != nil {
					sender.Gauge(fmt.Sprintf("docker.%s.total", stat.Name), float64(*stat.Total), "", nil)
				}
				percent := stat.GetPercentUsed()
				if !math.IsNaN(percent) {
					sender.Gauge(fmt.Sprintf("docker.%s.percent", stat.Name), percent, "", nil)
				}
			}
		}
	}
}

func (d *DockerCheck) collectVolumeMetrics(sender sender.Sender, du docker.Client) {
	if d.instance.CollectVolumeCount {
		attached, dangling, err := du.CountVolumes(context.TODO())
		if err != nil {
			d.Warnf("Error collecting volume stats: %s", err) //nolint:errcheck
		} else {
			sender.Gauge("docker.volume.count", float64(attached), "", []string{"volume_state:attached"})
			sender.Gauge("docker.volume.count", float64(dangling), "", []string{"volume_state:dangling"})
		}
	}
}

// setOkExitCodes defines the ok exit codes based on
// the default values and the OkExitCodes config field.
func (d *DockerCheck) setOkExitCodes() {
	d.okExitCodes = map[int]struct{}{}

	// Apply custom ok exit codes if defined.
	if len(d.instance.OkExitCodes) > 0 {
		for _, code := range d.instance.OkExitCodes {
			d.okExitCodes[code] = struct{}{}
		}

		return
	}

	// Set default ok exit codes.
	// 143 is returned when docker sends a SIGTERM to stop a container.
	d.okExitCodes = map[int]struct{}{0: {}, 143: {}}
}

func (d *DockerCheck) getImageTagsFromContainer(taggerEntityID types.EntityID, resolvedImageName string, isContainerExcluded bool) ([]string, error) {
	if isContainerExcluded {
		return getImageTags(resolvedImageName)
	}

	containerTags, err := d.tagger.Tag(taggerEntityID, types.LowCardinality)
	if err != nil {
		return nil, err
	}

	return containerTags, nil
}
