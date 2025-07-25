// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubelet

package kubelet

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"time"

	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/config/env"
	pkgerrors "github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics/provider"
	kutil "github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/option"
	"github.com/DataDog/datadog-agent/pkg/util/pointer"

	"k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

const (
	collectorID       = "kubelet"
	collectorPriority = 2

	contStatsCachePrefix    = "cs-"
	contNetStatsCachePrefix = "cns-"
	refreshCacheKey         = "refresh"

	kubeletCallTimeout     = 10 * time.Second
	kubeletCacheGCInterval = 30 * time.Second
)

func init() {
	provider.RegisterCollector(provider.CollectorFactory{
		ID: collectorID,
		Constructor: func(cache *provider.Cache, wmeta option.Option[workloadmeta.Component]) (provider.CollectorMetadata, error) {
			instance, ok := wmeta.Get()
			if !ok {
				return provider.CollectorMetadata{}, errors.New("missing workloadmeta component")
			}
			return newKubeletCollector(cache, instance)
		},
	})
}

type kubeletCollector struct {
	kubeletClient kutil.KubeUtilInterface
	metadataStore workloadmeta.Component
	statsCache    provider.Cache
	refreshLock   sync.Mutex
}

func newKubeletCollector(_ *provider.Cache, wmeta workloadmeta.Component) (provider.CollectorMetadata, error) {
	var collectorMetadata provider.CollectorMetadata

	if !env.IsFeaturePresent(env.Kubernetes) {
		return collectorMetadata, provider.ErrPermaFail
	}

	client, err := kutil.GetKubeUtil()
	if err != nil {
		return collectorMetadata, provider.ConvertRetrierErr(err)
	}

	collector := &kubeletCollector{
		kubeletClient: client,
		statsCache:    *provider.NewCache(kubeletCacheGCInterval),
		metadataStore: wmeta,
	}

	collectors := &provider.Collectors{
		Stats:                           provider.MakeRef[provider.ContainerStatsGetter](collector, collectorPriority),
		Network:                         provider.MakeRef[provider.ContainerNetworkStatsGetter](collector, collectorPriority),
		ContainerIDForPodUIDAndContName: provider.MakeRef[provider.ContainerIDForPodUIDAndContNameRetriever](collector, collectorPriority),
	}

	return provider.CollectorMetadata{
		ID: collectorID,
		Collectors: provider.CollectorCatalog{
			provider.NewRuntimeMetadata(string(provider.RuntimeNameContainerd), ""):                                 collectors,
			provider.NewRuntimeMetadata(string(provider.RuntimeNameContainerd), string(provider.RuntimeFlavorKata)): collectors,
			provider.NewRuntimeMetadata(string(provider.RuntimeNameCRIO), ""):                                       collectors,
			provider.NewRuntimeMetadata(string(provider.RuntimeNameDocker), ""):                                     collectors,
		},
	}, nil
}

// ContainerIDForPodUIDAndContName returns a container ID for the given pod uid
// and container name. Returns ("", nil) if the containerd ID was not found.
func (kc *kubeletCollector) ContainerIDForPodUIDAndContName(podUID, contName string, initCont bool, _ time.Duration) (string, error) {
	pod, err := kc.metadataStore.GetKubernetesPod(podUID)
	if err != nil {
		if pkgerrors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}

	var containers []workloadmeta.OrchestratorContainer
	if initCont {
		containers = pod.InitContainers
	} else {
		containers = append(pod.Containers, pod.EphemeralContainers...)
	}

	for _, container := range containers {
		if container.Name == contName {
			return container.ID, nil
		}
	}

	return "", nil
}

// GetContainerStats returns stats by container ID.
func (kc *kubeletCollector) GetContainerStats(_, containerID string, cacheValidity time.Duration) (*provider.ContainerStats, error) {
	currentTime := time.Now()

	containerStats, found, err := kc.statsCache.Get(currentTime, contStatsCachePrefix+containerID, cacheValidity)
	if found {
		if containerStats != nil {
			return containerStats.(*provider.ContainerStats), err
		}
		return nil, err
	}

	// Item missing from cache
	if err := kc.refreshContainerCache(currentTime, cacheValidity); err != nil {
		return nil, err
	}

	containerStats, found, err = kc.statsCache.Get(currentTime, contStatsCachePrefix+containerID, cacheValidity)
	if found {
		if containerStats != nil {
			return containerStats.(*provider.ContainerStats), err
		}
		return nil, err
	}

	return nil, nil
}

// GetContainerNetworkStats returns network stats by container ID.
func (kc *kubeletCollector) GetContainerNetworkStats(_, containerID string, cacheValidity time.Duration) (*provider.ContainerNetworkStats, error) {
	currentTime := time.Now()

	containerNetworkStats, found, err := kc.statsCache.Get(currentTime, contNetStatsCachePrefix+containerID, cacheValidity)
	if found {
		if containerNetworkStats != nil {
			return containerNetworkStats.(*provider.ContainerNetworkStats), err
		}
		return nil, err
	}

	// Item missing from cache
	if err := kc.refreshContainerCache(currentTime, cacheValidity); err != nil {
		return nil, err
	}

	containerNetworkStats, found, err = kc.statsCache.Get(currentTime, contNetStatsCachePrefix+containerID, cacheValidity)
	if found {
		if containerNetworkStats != nil {
			return containerNetworkStats.(*provider.ContainerNetworkStats), err
		}
		return nil, err
	}

	return nil, nil
}

func (kc *kubeletCollector) refreshContainerCache(currentTime time.Time, cacheValidity time.Duration) error {
	kc.refreshLock.Lock()
	defer kc.refreshLock.Unlock()

	// Not refreshing if last refresh is within cacheValidity
	_, found, err := kc.statsCache.Get(currentTime, refreshCacheKey, cacheValidity)
	if found {
		return err
	}

	statsSummary, err := kc.getStatsSummary()
	if err == nil {
		kc.processStatsSummary(currentTime, statsSummary)
	} else {
		log.Debugf("Unable to get stats from Kubelet, err: %v", err)
	}

	kc.statsCache.Store(currentTime, refreshCacheKey, nil, err)
	return err
}

func (kc *kubeletCollector) getStatsSummary() (*v1alpha1.Summary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kubeletCallTimeout)
	statsSummary, err := kc.kubeletClient.GetLocalStatsSummary(ctx)
	cancel()

	if err != nil {
		return nil, err
	}

	return statsSummary, err
}

func (kc *kubeletCollector) processStatsSummary(currentTime time.Time, statsSummary *v1alpha1.Summary) {
	if statsSummary == nil {
		return
	}

	for _, pod := range statsSummary.Pods {
		if len(pod.Containers) == 0 {
			continue
		}

		// Parsing network stats, need to store them by container anyway as it's the way it works currently
		// We use POD UID to generate an isolation group. It won't be network namespace FD, but it will still work
		// as all containers will get the same.
		// We could know if we're hostNetwork or not if we retrieve local POD list instead of relying on Workload meta,
		// albeit, with extra work. As this collector is designed to run in environment where we don't have access to
		// underlying host, it should not be an issue.
		podNetworkStats := &provider.ContainerNetworkStats{}
		convertNetworkStats(pod.Network, podNetworkStats)
		podNetworkStats.NetworkIsolationGroupID = pointer.Ptr(networkIDFromPODUID(pod.PodRef.UID))

		// As Metadata collector is running through polling, it can happen that we have newer PODs, containers
		metaPod, err := kc.metadataStore.GetKubernetesPod(pod.PodRef.UID)
		if err != nil || metaPod == nil {
			log.Debugf("Missing metadata for POD %s/%s - skipping, err: %v", pod.PodRef.Name, pod.PodRef.Namespace, err)
			continue
		}

		// In stats/summary we only have container name, need to remap to CID
		wlmContainers := metaPod.GetAllContainers()
		nameToCID := make(map[string]string, len(wlmContainers))
		for _, metaContainer := range wlmContainers {
			nameToCID[metaContainer.Name] = metaContainer.ID
		}

		// Parsing stats per container
		for _, container := range pod.Containers {
			cID := nameToCID[container.Name]
			if cID == "" {
				log.Debugf("Missing container ID for POD: %s/%s, container: %s - skipping, err: %v", pod.PodRef.Name, pod.PodRef.Namespace, container.Name, err)
				continue
			}

			containerStats := &provider.ContainerStats{}
			convertContainerStats(&container, containerStats)
			kc.statsCache.Store(currentTime, contStatsCachePrefix+cID, containerStats, nil)
			kc.statsCache.Store(currentTime, contNetStatsCachePrefix+cID, podNetworkStats, nil)
		}
	}
}

func convertContainerStats(kubeContainerStats *v1alpha1.ContainerStats, outContainerStats *provider.ContainerStats) {
	if kubeContainerStats == nil {
		return
	}

	if kubeContainerStats.CPU != nil {
		outContainerStats.Timestamp = kubeContainerStats.CPU.Time.Time
		outContainerStats.CPU = &provider.ContainerCPUStats{
			Total: pointer.UIntPtrToFloatPtr(kubeContainerStats.CPU.UsageCoreNanoSeconds),
		}
	}

	if kubeContainerStats.Memory != nil {
		outContainerStats.Memory = &provider.ContainerMemStats{
			UsageTotal: pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.UsageBytes),
			RSS:        pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.RSSBytes),
			Pgfault:    pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.PageFaults),
			Pgmajfault: pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.MajorPageFaults),
		}

		// On Linux `RSS` is set. On Windows only `WorkingSetBytes` is set
		if outContainerStats.Memory.RSS == nil {
			outContainerStats.Memory.UsageTotal = pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.WorkingSetBytes)
			outContainerStats.Memory.PrivateWorkingSet = pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.WorkingSetBytes)
		} else {
			outContainerStats.Memory.WorkingSet = pointer.UIntPtrToFloatPtr(kubeContainerStats.Memory.WorkingSetBytes)
		}
	}
}

func convertNetworkStats(podNetworkStats *v1alpha1.NetworkStats, outNetworkStats *provider.ContainerNetworkStats) {
	if podNetworkStats == nil {
		return
	}

	var sumBytesSent, sumBytesRcvd float64
	outNetworkStats.Timestamp = podNetworkStats.Time.Time
	outNetworkStats.Interfaces = make(map[string]provider.InterfaceNetStats, len(podNetworkStats.Interfaces))

	for _, interfaceStats := range podNetworkStats.Interfaces {
		fieldSet := false
		outInterfaceStats := provider.InterfaceNetStats{}

		if interfaceStats.TxBytes != nil {
			fieldSet = true
			sumBytesSent += float64(*interfaceStats.TxBytes)
			outInterfaceStats.BytesSent = pointer.UIntPtrToFloatPtr(interfaceStats.TxBytes)
		}
		if interfaceStats.RxBytes != nil {
			fieldSet = true
			sumBytesRcvd += float64(*interfaceStats.RxBytes)
			outInterfaceStats.BytesRcvd = pointer.UIntPtrToFloatPtr(interfaceStats.RxBytes)
		}

		if fieldSet {
			outNetworkStats.Interfaces[interfaceStats.Name] = outInterfaceStats
		}
	}

	if len(outNetworkStats.Interfaces) > 0 {
		outNetworkStats.BytesSent = &sumBytesSent
		outNetworkStats.BytesRcvd = &sumBytesRcvd
	}
}

func networkIDFromPODUID(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
