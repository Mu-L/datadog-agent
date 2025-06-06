// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package ksm

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	// time/tzdata embeds the timezone database to support legacy timezone names
	// (e.g. US/Central) used in upstream cronjob scheduling metric calculations
	_ "time/tzdata"

	"github.com/samber/lo"

	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	ksmstore "github.com/DataDog/datadog-agent/pkg/kubestatemetrics/store"
	"github.com/DataDog/datadog-agent/pkg/metrics/servicecheck"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// metricTransformerFunc is used to tweak or generate new metrics from a given KSM metric
// For name translation only please use metricNamesMapper instead
type metricTransformerFunc = func(sender.Sender, string, ksmstore.DDMetric, string, []string, time.Time)

var renamedResource = map[string]string{
	"nvidia_com_gpu":     "gpu",
	"amd_com_gpu":        "gpu",
	"gpu_intel_com_i915": "gpu",
	// Note: the following does not work out of the box, because it is filtered out of KSM metrics by default.
	//       and needs to be grabbed some other way. At time of commit, this is via customresources/node.go.
	//       More info: https://github.com/kubernetes/kube-state-metrics/issues/2027
	"kubernetes_io_network_bandwidth": "network_bandwidth",
}

var nodeAllowedResources = map[string]struct{}{
	"cpu":               {},
	"memory":            {},
	"pods":              {},
	"ephemeral_storage": {},
	"network_bandwidth": {},
	"gpu":               {},
}

var containerAllowedResources = map[string]struct{}{
	"cpu":               {},
	"memory":            {},
	"network_bandwidth": {},
	"gpu":               {},
}

func renameResource(resource string) string {
	if strings.HasPrefix(resource, "nvidia_com_mig") {
		return "gpu"
	}

	if renamed, found := renamedResource[resource]; found {
		return renamed
	}

	return resource
}

func resourceExtraTag(resource string) []string {
	if suffix, found := strings.CutPrefix(resource, "nvidia_com_mig_"); found {
		return []string{"mig_profile:" + strings.ReplaceAll(suffix, "_", "-")}
	}
	return nil
}

// resourceDDName returns the datadog name of the given resource with possibly extra tags.
func resourceDDName(resource string, allowedResources map[string]struct{}) (ddname string, extraTag []string, allowed bool) {
	// Add an extra tag
	extraTag = resourceExtraTag(resource)

	// Rename the resource
	ddname = renameResource(resource)

	// Check if the renamed resource is allowed
	_, allowed = allowedResources[ddname]

	return
}

// defaultMetricTransformers returns a map that contains KSM metric names and their corresponding transformer functions
// These metrics require more than a name translation to generate Datadog metrics, as opposed to the metrics in defaultMetricNamesMapper
// For reference see METRIC_TRANSFORMERS in KSM check V1
func defaultMetricTransformers() map[string]metricTransformerFunc {
	return map[string]metricTransformerFunc{
		"kube_pod_created":                              podCreationTransformer,
		"kube_pod_start_time":                           podStartTimeTransformer,
		"kube_pod_status_phase":                         podPhaseTransformer,
		"kube_pod_container_status_waiting_reason":      containerWaitingReasonTransformer,
		"kube_pod_container_status_terminated_reason":   containerTerminatedReasonTransformer,
		"kube_pod_container_extended_resource_requests": containerResourceRequestsTransformer,
		"kube_pod_container_resource_requests":          containerResourceRequestsTransformer,
		"kube_pod_container_resource_limits":            containerResourceLimitsTransformer,
		"kube_pod_container_extended_resource_limits":   containerResourceLimitsTransformer,
		"kube_cronjob_next_schedule_time":               cronJobNextScheduleTransformer,
		"kube_cronjob_status_last_schedule_time":        cronJobLastScheduleTransformer,
		"kube_cronjob_status_last_successful_time":      cronJobLastSuccessfulTransformer,
		"kube_job_complete":                             jobCompleteTransformer,
		"kube_job_duration":                             jobDurationTransformer,
		"kube_job_failed":                               jobFailedTransformer,
		"kube_job_status_failed":                        jobStatusFailedTransformer,
		"kube_job_status_succeeded":                     jobStatusSucceededTransformer,
		"kube_node_status_condition":                    nodeConditionTransformer,
		"kube_node_spec_unschedulable":                  nodeUnschedulableTransformer,
		"kube_node_status_allocatable":                  nodeAllocatableTransformer,
		"kube_node_status_extended_allocatable":         nodeAllocatableTransformer,
		"kube_node_status_capacity":                     nodeCapacityTransformer,
		"kube_node_status_extended_capacity":            nodeCapacityTransformer,
		"kube_node_created":                             nodeCreationTransformer,
		"kube_resourcequota":                            resourcequotaTransformer,
		"kube_limitrange":                               limitrangeTransformer,
		"kube_persistentvolume_status_phase":            pvPhaseTransformer,
		"kube_service_spec_type":                        serviceTypeTransformer,
		"kube_ingress_tls":                              removeSecretTransformer,
	}
}

// nodeConditionTransformer generates service checks based on the metric kube_node_status_condition
// It also submit the metric kubernetes_state.node.by_condition
func nodeConditionTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	if metric.Val != 1.0 {
		// Only consider active metrics
		return
	}

	condition, found := metric.Labels["condition"]
	if !found {
		log.Debugf("Couldn't find 'condition' label, ignoring service check for metric '%s'", name)
		return
	}

	s.Gauge(ksmMetricPrefix+"node.by_condition", metric.Val, hostname, tags)
	statusLabel, found := metric.Labels["status"]
	if !found {
		log.Debugf("Couldn't find 'status' label, ignoring service check for metric '%s'", name)
		return
	}

	serviceCheckName := ""
	var eventStatus servicecheck.ServiceCheckStatus
	switch condition {
	case "Ready":
		serviceCheckName = ksmMetricPrefix + "node.ready"
		eventStatus = statusForCondition(statusLabel, true)
	case "OutOfDisk":
		serviceCheckName = ksmMetricPrefix + "node.out_of_disk"
		eventStatus = statusForCondition(statusLabel, false)
	case "DiskPressure":
		serviceCheckName = ksmMetricPrefix + "node.disk_pressure"
		eventStatus = statusForCondition(statusLabel, false)
	case "NetworkUnavailable":
		serviceCheckName = ksmMetricPrefix + "node.network_unavailable"
		eventStatus = statusForCondition(statusLabel, false)
	case "MemoryPressure":
		serviceCheckName = ksmMetricPrefix + "node.memory_pressure"
		eventStatus = statusForCondition(statusLabel, false)
	default:
		log.Tracef("Invalid 'condition' label '%s', ignoring service check for metric '%s'", condition, name)
		return
	}

	node, found := metric.Labels["node"]
	if !found {
		log.Debugf("Couldn't find 'node' label, ignoring service check for metric '%s'", name)
		return
	}

	message := fmt.Sprintf("%s is currently reporting %s = %s", node, condition, statusLabel)
	s.ServiceCheck(serviceCheckName, eventStatus, hostname, tags, message)
}

// statusForCondition returns the right service check status based on the KSM label 'status'
// and the nature of the event whether a positive event or not
// e.g Ready is a positive event while MemoryPressure is not
func statusForCondition(status string, positiveEvent bool) servicecheck.ServiceCheckStatus {
	switch status {
	case "true":
		if positiveEvent {
			return servicecheck.ServiceCheckOK
		}
		return servicecheck.ServiceCheckCritical
	case "false":
		if positiveEvent {
			return servicecheck.ServiceCheckCritical
		}
		return servicecheck.ServiceCheckOK
	case "unknown":
		if positiveEvent {
			return servicecheck.ServiceCheckWarning
		}
		return servicecheck.ServiceCheckUnknown
	default:
		log.Tracef("Unknown 'status' label: '%s'", status)
		return servicecheck.ServiceCheckUnknown
	}
}

// nodeUnschedulableTransformer reports whether a node can schedule new pods
// It adds a tag 'status' that can be either 'schedulable' or 'unschedulable' and always report the metric value '1'
func nodeUnschedulableTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	status := ""
	switch metric.Val {
	case 0.0:
		status = "schedulable"
	case 1.0:
		status = "unschedulable"
	default:
		log.Debugf("Invalid metric value '%v', ignoring metric '%s'", metric.Val, name)
		return
	}
	tags = append(tags, "status:"+status)
	s.Gauge(ksmMetricPrefix+"node.status", 1, hostname, tags)
}

// submitAge generates a resource age or uptime metric based on a given timestamp
// The metric value must correspond to a timestamp
func submitAge(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	s.Gauge(name, float64(currentTime.Unix())-metric.Val, hostname, tags)
}

// nodeCreationTransformer generates the node age metric based on the creation timestamp
func nodeCreationTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	submitAge(s, ksmMetricPrefix+"node.age", metric, hostname, tags, currentTime)
}

// podCreationTransformer generates the pod age metric based on the creation timestamp
func podCreationTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	submitAge(s, ksmMetricPrefix+"pod.age", metric, hostname, tags, currentTime)
}

// podStartTimeTransformer generates the pod uptime metric based on the start time timestamp
func podStartTimeTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	submitAge(s, ksmMetricPrefix+"pod.uptime", metric, hostname, tags, currentTime)
}

// podPhaseTransformer sends status phase metrics for pods, the tag phase has the pod status
func podPhaseTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitActiveMetric(s, ksmMetricPrefix+"pod.status_phase", metric, hostname, tags)
}

var allowedWaitingReasons = map[string]struct{}{
	"errimagepull":               {},
	"imagepullbackoff":           {},
	"crashloopbackoff":           {},
	"containercreating":          {},
	"createcontainererror":       {},
	"invalidimagename":           {},
	"createcontainerconfigerror": {},
}

// containerWaitingReasonTransformer validates the container waiting reasons for metric kube_pod_container_status_waiting_reason
func containerWaitingReasonTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	if reason, found := metric.Labels["reason"]; found {
		// Filtering according to the reason here is paramount to limit cardinality
		if _, allowed := allowedWaitingReasons[strings.ToLower(reason)]; allowed {
			s.Gauge(ksmMetricPrefix+"container.status_report.count.waiting", metric.Val, hostname, tags)
		}
	}
}

var allowedTerminatedReasons = map[string]struct{}{
	"oomkilled":          {},
	"containercannotrun": {},
	"error":              {},
}

// containerTerminatedReasonTransformer validates the container waiting reasons for metric kube_pod_container_status_terminated_reason
func containerTerminatedReasonTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	if reason, found := metric.Labels["reason"]; found {
		// Filtering according to the reason here is paramount to limit cardinality
		if _, allowed := allowedTerminatedReasons[strings.ToLower(reason)]; allowed {
			s.Gauge(ksmMetricPrefix+"container.status_report.count.terminated", metric.Val, hostname, tags)
		}
	}
}

// containerResourceRequestsTransformer transforms the generic ksm resource request metrics into resource-specific metrics
func containerResourceRequestsTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitContainerResourceMetric(s, name, metric, hostname, tags, "requested")
}

// containerResourceLimitsTransformer transforms the generic ksm resource limit metrics into resource-specific metrics
func containerResourceLimitsTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitContainerResourceMetric(s, name, metric, hostname, tags, "limit")
}

// submitContainerResourceMetric can be called by container resource metric transformers to submit resource-specific metrics
// metricSuffix can be either requested or limit
func submitContainerResourceMetric(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, metricSuffix string) {
	resource, found := metric.Labels["resource"]
	if !found {
		log.Debugf("Couldn't find 'resource' label, ignoring resource metric '%s'", name)
		return
	}

	if ddname, extraTags, allowed := resourceDDName(resource, containerAllowedResources); allowed {
		tags = append(tags, extraTags...)
		s.Gauge(ksmMetricPrefix+"container."+ddname+"_"+metricSuffix, metric.Val, hostname, tags)
		return
	}
	log.Tracef("Ignoring container resource metric '%s': resource '%s' is not supported", name, resource)

}

// nodeAllocatableTransformer transforms the generic ksm node allocatable metrics into resource-specific metrics
func nodeAllocatableTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitNodeResourceMetric(s, name, metric, hostname, tags, "allocatable")
}

// nodeCapacityTransformer transforms the generic ksm node capacity metrics into resource-specific metrics
func nodeCapacityTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitNodeResourceMetric(s, name, metric, hostname, tags, "capacity")
}

// submitNodeResourceMetric can be called by node resource metric transformers to submit resource-specific metrics
// metricSuffix can be either allocatable or capacity
func submitNodeResourceMetric(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, metricSuffix string) {
	resource, found := metric.Labels["resource"]
	if !found {
		log.Debugf("Couldn't find 'resource' label, ignoring resource metric '%s'", name)
		return
	}

	if ddname, extraTags, allowed := resourceDDName(resource, nodeAllowedResources); allowed {
		tags = append(tags, extraTags...)
		s.Gauge(ksmMetricPrefix+"node."+ddname+"_"+metricSuffix, metric.Val, hostname, tags)
	} else {
		log.Tracef("Ignoring node resource metric '%s': resource '%s' is not supported", name, resource)
	}
}

// cronJobNextScheduleTransformer sends a service check to alert if the cronjob's next schedule is in the past
func cronJobNextScheduleTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	message := ""
	var status servicecheck.ServiceCheckStatus
	timeDiff := int64(metric.Val) - currentTime.Unix()
	if timeDiff >= 0 {
		status = servicecheck.ServiceCheckOK
	} else {
		status = servicecheck.ServiceCheckCritical
		message = fmt.Sprintf("The cron job check scheduled at %s is %d seconds late", time.Unix(int64(metric.Val), 0).UTC(), -timeDiff)
	}
	s.ServiceCheck(ksmMetricPrefix+"cronjob.on_schedule_check", status, hostname, tags, message)
}

// cronJobLastScheduleTransformer sends the duration since the last time the cronjob was scheduled
func cronJobLastScheduleTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	s.Gauge(ksmMetricPrefix+"cronjob.duration_since_last_schedule", float64(currentTime.Unix())-metric.Val, hostname, tags)
}

// cronJobLastSuccessfulTransformer sends the duration since the last time the cronjob succeeded
func cronJobLastSuccessfulTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, currentTime time.Time) {
	s.Gauge(ksmMetricPrefix+"cronjob.duration_since_last_successful", float64(currentTime.Unix())-metric.Val, hostname, tags)
}

// jobCompleteTransformer sends a metric and a service check based on kube_job_complete
func jobCompleteTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	for i, tag := range tags {
		if tag == "condition:true" {
			tags = append(tags[:i], tags[i+1:]...)
			break
		}
	}

	// jobMetric calls sender.Gauge. Like the rest of the sender.Sender funcs,
	// Gauge might modify the tags slice that it receives, so it's not safe to
	// reuse it later. We need the slice for the jobServiceCheck call, so we
	// need to create a copy.
	tagsCopy := make([]string, len(tags))
	copy(tagsCopy, tags)
	jobMetric(s, metric, ksmMetricPrefix+"job.completion.succeeded", hostname, tagsCopy)

	jobServiceCheck(s, metric, servicecheck.ServiceCheckOK, hostname, tags)
}

func jobDurationTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	jobMetric(s, metric, ksmMetricPrefix+"job.duration", hostname, tags)
}

// jobFailedTransformer sends a metric and a service check based on kube_job_failed
func jobFailedTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	for i, tag := range tags {
		if tag == "condition:true" {
			tags = append(tags[:i], tags[i+1:]...)
			break
		}
	}

	// Need a copy for the same reason as in the func jobCompleteTransformer defined above
	tagsCopy := make([]string, len(tags))
	copy(tagsCopy, tags)
	jobMetric(s, metric, ksmMetricPrefix+"job.completion.failed", hostname, tagsCopy)

	jobServiceCheck(s, metric, servicecheck.ServiceCheckCritical, hostname, tags)
}

// jobTimestampPattern extracts the timestamp in the job name label
// Used by trimJobTag to remove the timestamp from the job tag
// Expected job tag format: <job>-<timestamp>
var jobTimestampPattern = regexp.MustCompile(`(-\d{4,10}$)`)

// trimJobTag removes the timestamp from the job name tag
// Expected job tag format: <job>-<timestamp>
func trimJobTag(tag string) (string, bool) {
	trimmed := jobTimestampPattern.ReplaceAllString(tag, "")
	return trimmed, tag != trimmed
}

var jobFailureReasons = map[string]struct{}{
	"backofflimitexceeded": {},
	"deadlineexceeded":     {},
}

func validJobFailureReason(reason string) bool {
	_, ok := jobFailureReasons[strings.ToLower(reason)]
	return ok
}

// validateJob detects active jobs and adds the `kube_cronjob` tag
func validateJob(val float64, tags []string) ([]string, bool) {
	kubeCronjob := ""
	for i, tag := range tags {
		if strings.HasPrefix(tag, "reason:") {
			if v := strings.TrimPrefix(tag, "reason:"); !validJobFailureReason(v) {
				tags = append(tags[:i], tags[i+1:]...)
				continue
			}
		}
		split := strings.Split(tag, ":")
		if len(split) == 2 && split[0] == "kube_job" || split[0] == "job" || split[0] == "job_name" {
			// Trim the timestamp suffix to avoid high cardinality
			if name, trimmed := trimJobTag(split[1]); trimmed {
				// The trimmed job name corresponds to the parent cronjob name
				// https://github.com/kubernetes/kubernetes/blob/v1.21.0/pkg/controller/cronjob/utils.go#L240
				kubeCronjob = name
			}
		}
	}

	if kubeCronjob != "" {
		tags = append(tags, "kube_cronjob:"+kubeCronjob)
	}
	return tags, val == 1.0
}

// jobServiceCheck sends a service check for jobs
func jobServiceCheck(s sender.Sender, metric ksmstore.DDMetric, status servicecheck.ServiceCheckStatus, hostname string, tags []string) {
	if strippedTags, valid := validateJob(metric.Val, tags); valid {
		s.ServiceCheck(ksmMetricPrefix+"job.complete", status, hostname, strippedTags, "")
	}
}

// jobStatusSucceededTransformer sends a metric based on kube_job_status_succeeded
func jobStatusSucceededTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	jobMetric(s, metric, ksmMetricPrefix+"job.succeeded", hostname, tags)
}

// jobStatusFailedTransformer sends a metric based on kube_job_status_failed
//
// The KSM upstream `kube_job_status_failed` metric has the following behavior:
// If there’s no failed pod, the metric has no `reason` tag and its value is 0.
// If there are failed pod(s), there are several metrics generated with a different `reason` tag.
// The metric with the `reason` tag that correspond to the last failure has the value 1 whereas
// the metrics with the other `reason` tags have a value of 0.
//
// In order to reduce the cardinality, we are here removing the `reason` tag.
// The resulting datadog metric is 0 if there are no failed pods and 1 otherwise.
func jobStatusFailedTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	// Remove the `reason` tag to reduce the cardinality
	reasonTagIndex := -1
	for idx, tag := range tags {
		if strings.HasPrefix(tag, "reason:") {
			reasonTagIndex = idx
			break
		}
	}

	if reasonTagIndex != -1 && metric.Val == 0 {
		return
	}

	jobMetric(s, metric, ksmMetricPrefix+"job.failed", hostname, tags)
}

// jobMetric sends a gauge for job status
func jobMetric(s sender.Sender, metric ksmstore.DDMetric, metricName string, hostname string, tags []string) {
	strippedTags, _ := validateJob(metric.Val, tags)
	s.Gauge(metricName, metric.Val, hostname, strippedTags)
}

// resourcequotaTransformer generates dedicated metrics per resource per type from the kube_resourcequota metric
func resourcequotaTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	resource, found := metric.Labels["resource"]
	if !found {
		log.Debugf("Couldn't find 'resource' label, ignoring metric '%s'", name)
		return
	}
	quotaType, found := metric.Labels["type"]
	if !found {
		log.Debugf("Couldn't find 'type' label, ignoring metric '%s'", name)
		return
	}
	if quotaType == "hard" {
		quotaType = "limit"
	}
	metricName := ksmMetricPrefix + fmt.Sprintf("resourcequota.%s.%s", resource, quotaType)
	s.Gauge(metricName, metric.Val, hostname, tags)
}

// constraintsMapper is used by the kube_limitrange metric transformer
var constraintsMapper = map[string]string{
	"min":                  "min",
	"max":                  "max",
	"default":              "default",
	"defaultRequest":       "default_request",
	"maxLimitRequestRatio": "max_limit_request_ratio",
}

// limitrangeTransformer generates dedicated metrics per resource per type from the kube_limitrange metric
func limitrangeTransformer(s sender.Sender, name string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	constraintLabel, found := metric.Labels["constraint"]
	if !found {
		log.Debugf("Couldn't find 'constraint' label, ignoring metric '%s'", name)
		return
	}
	constraint, found := constraintsMapper[constraintLabel]
	if !found {
		log.Debugf("Constraint '%s' unsupported for metric '%s'", constraint, name)
		return
	}
	resource, found := metric.Labels["resource"]
	if !found {
		log.Debugf("Couldn't find 'resource' label, ignoring metric '%s'", name)
		return
	}
	metricName := ksmMetricPrefix + fmt.Sprintf("limitrange.%s.%s", resource, constraint)
	s.Gauge(metricName, metric.Val, hostname, tags)
}

// submitActiveMetrics only sends metrics with value '1'
func submitActiveMetric(s sender.Sender, metricName string, metric ksmstore.DDMetric, hostname string, tags []string) {
	if metric.Val != 1.0 {
		// Only consider active metrics
		return
	}
	s.Gauge(metricName, 1, hostname, tags)
}

// pvPhaseTransformer generates metrics per persistentvolume and per phase from the kube_persistentvolume_status_phase metric
func pvPhaseTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitActiveMetric(s, ksmMetricPrefix+"persistentvolume.by_phase", metric, hostname, tags)
}

// serviceTypeTransformer generates metrics per service, namespace, and type from the kube_service_spec_type metric
func serviceTypeTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	submitActiveMetric(s, ksmMetricPrefix+"service.type", metric, hostname, tags)
}

// removeSecretTransformer removes the secret tag from the kube_ingress_tls metric
func removeSecretTransformer(s sender.Sender, _ string, metric ksmstore.DDMetric, hostname string, tags []string, _ time.Time) {
	if len(tags) > 0 {
		tags = lo.Filter(tags, func(x string, _ int) bool { return !strings.HasPrefix(x, "secret:") })
	}
	s.Gauge(ksmMetricPrefix+"ingress.tls", metric.Val, hostname, tags)
}
