// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package config holds config related files
package config

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	logsconfig "github.com/DataDog/datadog-agent/comp/logs/agent/config"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	configUtils "github.com/DataDog/datadog-agent/pkg/config/utils"
	logshttp "github.com/DataDog/datadog-agent/pkg/logs/client/http"
	pconfig "github.com/DataDog/datadog-agent/pkg/security/probe/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	sysconfig "github.com/DataDog/datadog-agent/pkg/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
)

const (
	// ADMinMaxDumSize represents the minimum value for runtime_security_config.activity_dump.max_dump_size
	ADMinMaxDumSize = 100
)

var (
	// defaultKernelCompilationFlags are the kernel compilation flags checked by CWS
	// This list was moved here, away from the config/ package, to reduce the size of the agent metadata payload in REDAPL.
	defaultKernelCompilationFlags = []string{
		// memory management hardening
		"CONFIG_DEBUG_KERNEL",
		"CONFIG_DEBUG_RODATA",
		"CONFIG_STRICT_KERNEL_RWX",
		"CONFIG_ARCH_OPTIONAL_KERNEL_RWX",
		"CONFIG_ARCH_HAS_STRICT_KERNEL_RWX",
		"CONFIG_DEBUG_WX",
		"CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
		"CONFIG_INIT_ON_FREE_DEFAULT_ON",
		"CONFIG_IOMMU_DEFAULT_DMA_STRICT",
		"CONFIG_IOMMU_DEFAULT_PASSTHROUGH",
		"CONFIG_KFENCE",
		"CONFIG_HAVE_ARCH_KFENCE",
		"CONFIG_KFENCE_SAMPLE_INTERVAL",
		"CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT",
		"CONFIG_CC_STACKPROTECTOR",
		"CONFIG_CC_STACKPROTECTOR_STRONG",
		"CONFIG_STACKPROTECTOR",
		"CONFIG_STACKPROTECTOR_STRONG",
		"CONFIG_DEVMEM",
		"CONFIG_STRICT_DEVMEM",
		"CONFIG_IO_STRICT_DEVMEM",
		"CONFIG_SCHED_STACK_END_CHECK",
		"CONFIG_HARDENED_USERCOPY",
		"CONFIG_HARDENED_USERCOPY_FALLBACK",
		"CONFIG_HARDENED_USERCOPY_PAGESPAN",
		"CONFIG_VMAP_STACK",
		"CONFIG_REFCOUNT_FULL",
		"CONFIG_FORTIFY_SOURCE",
		"CONFIG_ACPI_CUSTOM_METHOD",
		"CONFIG_DEVKMEM",
		"CONFIG_PROC_KCORE",
		"CONFIG_COMPAT_VDSO",
		"CONFIG_SECURITY_DMESG_RESTRICT",
		"CONFIG_RETPOLINE",
		"CONFIG_LEGACY_VSYSCALL_NONE",
		"CONFIG_LEGACY_VSYSCALL_EMULATE",
		"CONFIG_LEGACY_VSYSCALL_XONLY",
		"CONFIG_X86_VSYSCALL_EMULATION",
		"CONFIG_SHUFFLE_PAGE_ALLOCATOR",
		// protect kernel data structures
		"CONFIG_DEBUG_CREDENTIALS",
		"CONFIG_DEBUG_NOTIFIERS",
		"CONFIG_DEBUG_LIST",
		"CONFIG_DEBUG_SG",
		"CONFIG_BUG_ON_DATA_CORRUPTION",
		// harden the memory allocator
		"CONFIG_SLAB_FREELIST_RANDOM",
		"CONFIG_SLUB",
		"CONFIG_SLAB_FREELIST_HARDENED",
		"CONFIG_SLAB_MERGE_DEFAULT",
		"CONFIG_SLUB_DEBUG",
		"CONFIG_PAGE_POISONING",
		"CONFIG_PAGE_POISONING_NO_SANITY",
		"CONFIG_PAGE_POISONING_ZERO",
		"CONFIG_COMPAT_BRK",
		// harden the management of kernel modules
		"CONFIG_MODULES",
		"CONFIG_STRICT_MODULE_RWX",
		"CONFIG_MODULE_SIG",
		"CONFIG_MODULE_SIG_FORCE",
		"CONFIG_MODULE_SIG_ALL",
		"CONFIG_MODULE_SIG_SHA512",
		"CONFIG_MODULE_SIG_HASH",
		// handle abnormal situations
		"CONFIG_BUG",
		"CONFIG_PANIC_ON_OOPS",
		"CONFIG_PANIC_TIMEOUT",
		// configure kernel security functions
		"CONFIG_MULTIUSER",
		"CONFIG_SECURITY",
		"CONFIG_SECCOMP",
		"CONFIG_SECCOMP_FILTER",
		"CONFIG_SECURITY_YAMA",
		"CONFIG_SECURITY_WRITABLE_HOOKS",
		"CONFIG_SECURITY_SELINUX",
		"CONFIG_SECURITY_SELINUX_DISABLE",
		"CONFIG_BPF_LSM",
		"CONFIG_SECURITY_SMACK",
		"CONFIG_SECURITY_TOMOYO",
		"CONFIG_SECURITY_APPARMOR",
		"CONFIG_SECURITY_LOCKDOWN_LSM",
		"CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY",
		"CONFIG_SECURITY_LANDLOCK",
		"CONFIG_LSM",
		"CONFIG_INTEGRITY_AUDIT",
		"CONFIG_INTEGRITY",
		"CONFIG_INTEGRITY_SIGNATURE",
		"CONFIG_INTEGRITY_ASYMMETRIC_KEYS",
		"CONFIG_INTEGRITY_TRUSTED_KEYRING",
		"CONFIG_INTEGRITY_PLATFORM_KEYRING",
		"CONFIG_INTEGRITY_MACHINE_KEYRING",
		// configure compiler plugins
		"CONFIG_GCC_PLUGINS",
		"CONFIG_GCC_PLUGIN_LATENT_ENTROPY",
		"CONFIG_GCC_PLUGIN_STACKLEAK",
		"CONFIG_GCC_PLUGIN_STRUCTLEAK",
		"CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL",
		"CONFIG_GCC_PLUGIN_RANDSTRUCT",
		"CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE",
		// configure the IP stack
		"CONFIG_IPV6",
		"CONFIG_SYN_COOKIES",
		// various kernel behavior
		"CONFIG_KEXEC",
		"CONFIG_KEXEC_SIG",
		"CONFIG_KEXEC_SIG_FORCE",
		"CONFIG_HIBERNATION",
		"CONFIG_BINFMT_MISC",
		"CONFIG_LEGACY_PTYS",
		// options for x86_32 bit architectures
		"CONFIG_HIGHMEM64G",
		"CONFIG_X86_PAE",
		// options for x86_64 or arm64 architectures
		"CONFIG_X86_64",
		"CONFIG_DEFAULT_MMAP_MIN_ADDR",
		"CONFIG_RANDOMIZE_BASE",
		"CONFIG_RANDOMIZE_MEMORY",
		"CONFIG_PAGE_TABLE_ISOLATION",
		"CONFIG_IA32_EMULATION",
		"CONFIG_MODIFY_LDT_SYSCALL",
		"CONFIG_ARM64_SW_TTBR0_PAN",
		"CONFIG_UNMAP_KERNEL_AT_EL0",
	}
)

// Policy represents a policy file in the configuration file
type Policy struct {
	Name  string   `mapstructure:"name"`
	Files []string `mapstructure:"files"`
	Tags  []string `mapstructure:"tags"`
}

// RuntimeSecurityConfig holds the configuration for the runtime security agent
type RuntimeSecurityConfig struct {
	// RuntimeEnabled defines if the runtime security module should be enabled
	RuntimeEnabled bool
	// PoliciesDir defines the folder in which the policy files are located
	PoliciesDir string
	// PolicyMonitorEnabled enable policy monitoring
	PolicyMonitorEnabled bool
	// PolicyMonitorPerRuleEnabled enabled per-rule policy monitoring
	PolicyMonitorPerRuleEnabled bool
	// PolicyMonitorReportInternalPolicies enable internal policies monitoring
	PolicyMonitorReportInternalPolicies bool
	// SocketPath is the path to the socket that is used to communicate with the security agent
	SocketPath string
	// EventServerBurst defines the maximum burst of events that can be sent over the grpc server
	EventServerBurst int
	// EventServerRate defines the grpc server rate at which events can be sent
	EventServerRate int
	// EventServerRetention defines an event retention period so that some fields can be resolved
	EventServerRetention time.Duration
	// FIMEnabled determines whether fim rules will be loaded
	FIMEnabled bool
	// SelfTestEnabled defines if the self tests should be executed at startup or not
	SelfTestEnabled bool
	// SelfTestSendReport defines if a self test event will be emitted
	SelfTestSendReport bool
	// RemoteConfigurationEnabled defines whether to use remote monitoring
	RemoteConfigurationEnabled bool
	// RemoteConfigurationDumpPolicies defines whether to dump remote config policy
	RemoteConfigurationDumpPolicies bool
	// LogPatterns pattern to be used by the logger for trace level
	LogPatterns []string
	// LogTags tags to be used by the logger for trace level
	LogTags []string
	// EnvAsTags convert envs to tags
	EnvAsTags []string
	// HostServiceName string
	HostServiceName string
	// OnDemandEnabled defines whether the on-demand probes should be enabled
	OnDemandEnabled bool
	// OnDemandRateLimiterEnabled defines whether the on-demand probes rate limit getting hit disabled the on demand probes
	OnDemandRateLimiterEnabled bool
	// ReducedProcPidCacheSize defines whether the `proc_cache` and `pid_cache` map should use reduced size
	ReducedProcPidCacheSize bool

	// InternalMonitoringEnabled determines if the monitoring events of the agent should be sent to Datadog
	InternalMonitoringEnabled bool

	// ActivityDumpEnabled defines if the activity dump manager should be enabled
	ActivityDumpEnabled bool
	// ActivityDumpCleanupPeriod defines the period at which the activity dump manager should perform its cleanup
	// operation.
	ActivityDumpCleanupPeriod time.Duration
	// ActivityDumpTagsResolutionPeriod defines the period at which the activity dump manager should try to resolve
	// missing container tags.
	ActivityDumpTagsResolutionPeriod time.Duration
	// ActivityDumpLoadControlPeriod defines the period at which the activity dump manager should trigger the load controller
	ActivityDumpLoadControlPeriod time.Duration
	// ActivityDumpLoadControlMinDumpTimeout defines minimal duration of a activity dump recording
	ActivityDumpLoadControlMinDumpTimeout time.Duration

	// ActivityDumpTracedCgroupsCount defines the maximum count of cgroups that should be monitored concurrently. Leave this parameter to 0 to prevent the generation
	// of activity dumps based on cgroups.
	ActivityDumpTracedCgroupsCount int
	// ActivityDumpCgroupsManagers defines the cgroup managers we generate dumps for.
	ActivityDumpCgroupsManagers []string

	// ActivityDumpTracedEventTypes defines the list of events that should be captured in an activity dump. Leave this
	// parameter empty to monitor all event types. If not already present, the `exec` event will automatically be added
	// to this list.
	ActivityDumpTracedEventTypes []model.EventType
	// ActivityDumpCgroupDumpTimeout defines the cgroup activity dumps timeout.
	ActivityDumpCgroupDumpTimeout time.Duration
	// ActivityDumpRateLimiter defines the kernel rate of max events per sec for activity dumps.
	ActivityDumpRateLimiter uint16
	// ActivityDumpCgroupWaitListTimeout defines the time to wait before a cgroup can be dumped again.
	ActivityDumpCgroupWaitListTimeout time.Duration
	// ActivityDumpCgroupDifferentiateArgs defines if system-probe should differentiate process nodes using process
	// arguments for dumps.
	ActivityDumpCgroupDifferentiateArgs bool
	// ActivityDumpLocalStorageDirectory defines the output directory for the activity dumps and graphs. Leave
	// this field empty to prevent writing any output to disk.
	ActivityDumpLocalStorageDirectory string
	// ActivityDumpLocalStorageFormats defines the formats that should be used to persist the activity dumps locally.
	ActivityDumpLocalStorageFormats []StorageFormat
	// ActivityDumpLocalStorageCompression defines if the local storage should compress the persisted data.
	ActivityDumpLocalStorageCompression bool
	// ActivityDumpLocalStorageMaxDumpsCount defines the maximum count of activity dumps that should be kept locally.
	// When the limit is reached, the oldest dumps will be deleted first.
	ActivityDumpLocalStorageMaxDumpsCount int
	// ActivityDumpSyscallMonitorPeriod defines the minimum amount of time to wait between 2 syscalls event for the same
	// process.
	ActivityDumpSyscallMonitorPeriod time.Duration
	// ActivityDumpMaxDumpCountPerWorkload defines the maximum amount of dumps that the agent should send for a workload
	ActivityDumpMaxDumpCountPerWorkload int
	// ActivityDumpWorkloadDenyList defines the list of workloads for which we shouldn't generate dumps. Workloads should
	// be provided as strings in the following format "{image_name}:[{image_tag}|*]". If "*" is provided instead of a
	// specific image tag, then the entry will match any workload with the input {image_name} regardless of their tag.
	ActivityDumpWorkloadDenyList []string
	// ActivityDumpTagRulesEnabled enable the tagging of nodes with matched rules
	ActivityDumpTagRulesEnabled bool
	// ActivityDumpSilentWorkloadsDelay defines the minimum amount of time to wait before the activity dump manager will start tracing silent workloads
	ActivityDumpSilentWorkloadsDelay time.Duration
	// ActivityDumpSilentWorkloadsTicker configures ticker that will check if a workload is silent and should be traced
	ActivityDumpSilentWorkloadsTicker time.Duration
	// ActivityDumpAutoSuppressionEnabled bool do not send event if part of a dump
	ActivityDumpAutoSuppressionEnabled bool

	// # Dynamic configuration fields:
	// ActivityDumpMaxDumpSize defines the maximum size of a dump
	ActivityDumpMaxDumpSize func() int

	// SecurityProfileEnabled defines if the Security Profile manager should be enabled
	SecurityProfileEnabled bool
	// SecurityProfileMaxImageTags defines the maximum number of profile versions to maintain
	SecurityProfileMaxImageTags int
	// SecurityProfileDir defines the directory in which Security Profiles are stored
	SecurityProfileDir string
	// SecurityProfileWatchDir defines if the Security Profiles directory should be monitored
	SecurityProfileWatchDir bool
	// SecurityProfileCacheSize defines the count of Security Profiles held in cache
	SecurityProfileCacheSize int
	// SecurityProfileMaxCount defines the maximum number of Security Profiles that may be evaluated concurrently
	SecurityProfileMaxCount int
	// SecurityProfileDNSMatchMaxDepth defines the max depth of subdomain to be matched for DNS anomaly detection (0 to match everything)
	SecurityProfileDNSMatchMaxDepth int

	// SecurityProfileAutoSuppressionEnabled do not send event if part of a profile
	SecurityProfileAutoSuppressionEnabled bool
	// SecurityProfileAutoSuppressionEventTypes defines the list of event types the can be auto suppressed using security profiles
	SecurityProfileAutoSuppressionEventTypes []model.EventType

	// AnomalyDetectionEventTypes defines the list of events that should be allowed to generate anomaly detections
	AnomalyDetectionEventTypes []model.EventType
	// AnomalyDetectionDefaultMinimumStablePeriod defines the default minimum amount of time during which the events
	// that diverge from their profiles are automatically added in their profiles without triggering an anomaly detection
	// event.
	AnomalyDetectionDefaultMinimumStablePeriod time.Duration
	// AnomalyDetectionMinimumStablePeriods defines the minimum amount of time per event type during which the events
	// that diverge from their profiles are automatically added in their profiles without triggering an anomaly detection
	// event.
	AnomalyDetectionMinimumStablePeriods map[model.EventType]time.Duration
	// AnomalyDetectionUnstableProfileTimeThreshold defines the maximum amount of time to wait until a profile that
	// hasn't reached a stable state is considered as unstable.
	AnomalyDetectionUnstableProfileTimeThreshold time.Duration
	// AnomalyDetectionUnstableProfileSizeThreshold defines the maximum size a profile can reach past which it is
	// considered unstable
	AnomalyDetectionUnstableProfileSizeThreshold int64
	// AnomalyDetectionWorkloadWarmupPeriod defines the duration we ignore the anomaly detections for
	// because of workload warm up
	AnomalyDetectionWorkloadWarmupPeriod time.Duration
	// AnomalyDetectionRateLimiterPeriod is the duration during which a limited number of anomaly detection events are allowed
	AnomalyDetectionRateLimiterPeriod time.Duration
	// AnomalyDetectionRateLimiterNumEventsAllowed is the number of anomaly detection events allowed per duration by the rate limiter
	AnomalyDetectionRateLimiterNumEventsAllowed int
	// AnomalyDetectionRateLimiterNumKeys is the number of keys in the rate limiter
	AnomalyDetectionRateLimiterNumKeys int
	// AnomalyDetectionTagRulesEnabled defines if the events that triggered anomaly detections should be tagged with the
	// rules they might have matched.
	AnomalyDetectionTagRulesEnabled bool
	// AnomalyDetectionSilentRuleEventsEnabled do not send rule event if also part of an anomaly event
	AnomalyDetectionSilentRuleEventsEnabled bool
	// AnomalyDetectionEnabled defines if we should send anomaly detection events
	AnomalyDetectionEnabled bool

	// SBOMResolverEnabled defines if the SBOM resolver should be enabled
	SBOMResolverEnabled bool
	// SBOMResolverWorkloadsCacheSize defines the count of SBOMs to keep in memory in order to prevent re-computing
	// the SBOMs of short-lived and periodical workloads
	SBOMResolverWorkloadsCacheSize int
	// SBOMResolverHostEnabled defines if the SBOM resolver should compute the host's SBOM
	SBOMResolverHostEnabled bool
	// SBOMResolverAnalyzers defines the list of analyzers that should be used to compute the SBOM
	SBOMResolverAnalyzers []string

	// HashResolverEnabled defines if the hash resolver should be enabled
	HashResolverEnabled bool
	// HashResolverMaxFileSize defines the maximum size of the files that the hash resolver is allowed to hash
	HashResolverMaxFileSize int64
	// HashResolverMaxHashRate defines the rate at which the hash resolver may compute hashes
	HashResolverMaxHashRate int
	// HashResolverHashAlgorithms defines the hashes that hash resolver needs to compute
	HashResolverHashAlgorithms []model.HashAlgorithm
	// HashResolverEventTypes defines the list of event which files may be hashed
	HashResolverEventTypes []model.EventType
	// HashResolverCacheSize defines the number of hashes to keep in cache
	HashResolverCacheSize int
	// HashResolverReplace is used to apply specific hash to specific file path
	HashResolverReplace map[string]string

	// SysCtlEnabled defines if the sysctl event should be enabled
	SysCtlEnabled bool
	// SysCtlSnapshotEnabled defines if the sysctl snapshot feature should be enabled
	SysCtlSnapshotEnabled bool
	// SysCtlSnapshotPeriod defines at which time interval a new snapshot of sysctl parameters should be sent
	SysCtlSnapshotPeriod time.Duration
	// SysCtlSnapshotIgnoredBaseNames defines the list of basenaes that should be ignored from the snapshot
	SysCtlSnapshotIgnoredBaseNames []string
	// SysCtlSnapshotKernelCompilationFlags defines the list of kernel compilation flags that should be collected by the agent
	SysCtlSnapshotKernelCompilationFlags map[string]uint8

	// UserSessionsCacheSize defines the size of the User Sessions cache size
	UserSessionsCacheSize int

	// EBPFLessEnabled enables the ebpfless probe
	EBPFLessEnabled bool
	// EBPFLessSocket defines the socket used for the communication between system-probe and the ebpfless source
	EBPFLessSocket string

	// Enforcement capabilities
	// EnforcementEnabled defines if the enforcement capability should be enabled
	EnforcementEnabled bool
	// EnforcementRawSyscallEnabled defines if the enforcement should be performed using the sys_enter tracepoint
	EnforcementRawSyscallEnabled bool
	EnforcementBinaryExcluded    []string
	EnforcementRuleSourceAllowed []string
	// EnforcementDisarmerContainerEnabled defines if an enforcement rule should be disarmed when hitting too many different containers
	EnforcementDisarmerContainerEnabled bool
	// EnforcementDisarmerContainerMaxAllowed defines the maximum number of different containers that can trigger an enforcement rule
	// within a period before the enforcement is disarmed for this rule
	EnforcementDisarmerContainerMaxAllowed int
	// EnforcementDisarmerContainerPeriod defines the period during which EnforcementDisarmerContainerMaxAllowed is checked
	EnforcementDisarmerContainerPeriod time.Duration
	// EnforcementDisarmerExecutableEnabled defines if an enforcement rule should be disarmed when hitting too many different executables
	EnforcementDisarmerExecutableEnabled bool
	// EnforcementDisarmerExecutableMaxAllowed defines the maximum number of different executables that can trigger an enforcement rule
	// within a period before the enforcement is disarmed for this rule
	EnforcementDisarmerExecutableMaxAllowed int
	// EnforcementDisarmerExecutablePeriod defines the period during which EnforcementDisarmerExecutableMaxAllowed is checked
	EnforcementDisarmerExecutablePeriod time.Duration

	//WindowsFilenameCacheSize is the max number of filenames to cache
	WindowsFilenameCacheSize int
	//WindowsRegistryCacheSize is the max number of registry paths to cache
	WindowsRegistryCacheSize int

	// ETWEventsChannelSize windows specific ETW channel buffer size
	ETWEventsChannelSize int

	//ETWEventsMaxBuffers sets the maximumbuffers argument to ETW
	ETWEventsMaxBuffers int

	// WindowsProbeChannelUnbuffered defines if the windows probe channel should be unbuffered
	WindowsProbeBlockOnChannelSend bool

	WindowsWriteEventRateLimiterMaxAllowed int
	WindowsWriteEventRateLimiterPeriod     time.Duration

	// IMDSIPv4 is used to provide a custom IP address for the IMDS endpoint
	IMDSIPv4 uint32

	// SendEventFromSystemProbe defines when the event are sent directly from system-probe
	SendEventFromSystemProbe bool

	// FileMetadataResolverEnabled defines if the file metadata is enabled
	FileMetadataResolverEnabled bool
}

// Config defines a security config
type Config struct {
	// Probe Config
	Probe *pconfig.Config

	// CWS specific parameters
	RuntimeSecurity *RuntimeSecurityConfig
}

// NewConfig returns a new Config object
func NewConfig() (*Config, error) {
	probeConfig, err := pconfig.NewConfig()
	if err != nil {
		return nil, err
	}

	rsConfig, err := NewRuntimeSecurityConfig()
	if err != nil {
		return nil, err
	}

	return &Config{
		Probe:           probeConfig,
		RuntimeSecurity: rsConfig,
	}, nil
}

// NewRuntimeSecurityConfig returns the runtime security (CWS) config, build from the system probe one
func NewRuntimeSecurityConfig() (*RuntimeSecurityConfig, error) {
	sysconfig.Adjust(pkgconfigsetup.SystemProbe())

	allEventTypes := make([]model.EventType, 0, model.MaxKernelEventType)

	var eventType model.EventType
	for i := uint64(0); i != uint64(model.MaxKernelEventType); i++ {
		eventType = model.EventType(i)
		allEventTypes = append(allEventTypes, eventType)
	}

	// parseEventTypeStringSlice converts a string list to a list of event types
	parseEventTypeStringSlice := func(eventTypes []string) []model.EventType {
		var output []model.EventType
		for _, eventTypeStr := range eventTypes {
			if eventTypeStr == "*" {
				return allEventTypes
			}
			eventType, err := model.ParseEvalEventType(eventTypeStr)
			if err != nil {
				seclog.Errorf("failed to parse event type '%s': %v", eventTypeStr, err)
				continue
			}
			if eventType == model.UnknownEventType {
				seclog.Errorf("unknown event type '%s'", eventTypeStr)
				continue
			}
			output = append(output, eventType)
		}
		return output
	}

	anomalyDetectionMinimumStablePeriods, err := parseEventTypeDurations(pkgconfigsetup.SystemProbe(), "runtime_security_config.security_profile.anomaly_detection.minimum_stable_period")
	if err != nil {
		return nil, err
	}

	rsConfig := &RuntimeSecurityConfig{
		RuntimeEnabled: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.enabled"),
		FIMEnabled:     pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.fim_enabled"),

		// Windows specific
		WindowsFilenameCacheSize:               pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.windows_filename_cache_max"),
		WindowsRegistryCacheSize:               pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.windows_registry_cache_max"),
		ETWEventsChannelSize:                   pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.etw_events_channel_size"),
		WindowsProbeBlockOnChannelSend:         pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.windows_probe_block_on_channel_send"),
		WindowsWriteEventRateLimiterMaxAllowed: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.windows_write_event_rate_limiter_max_allowed"),
		WindowsWriteEventRateLimiterPeriod:     pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.windows_write_event_rate_limiter_period"),

		SocketPath:           pkgconfigsetup.SystemProbe().GetString("runtime_security_config.socket"),
		EventServerBurst:     pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.event_server.burst"),
		EventServerRate:      pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.event_server.rate"),
		EventServerRetention: pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.event_server.retention"),

		SelfTestEnabled:                 pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.self_test.enabled"),
		SelfTestSendReport:              pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.self_test.send_report"),
		RemoteConfigurationEnabled:      isRemoteConfigEnabled(),
		RemoteConfigurationDumpPolicies: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.remote_configuration.dump_policies"),

		OnDemandEnabled:            pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.on_demand.enabled"),
		OnDemandRateLimiterEnabled: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.on_demand.rate_limiter.enabled"),
		ReducedProcPidCacheSize:    pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.reduced_proc_pid_cache_size"),

		// policy & ruleset
		PoliciesDir:                         pkgconfigsetup.SystemProbe().GetString("runtime_security_config.policies.dir"),
		PolicyMonitorEnabled:                pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.policies.monitor.enabled"),
		PolicyMonitorPerRuleEnabled:         pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.policies.monitor.per_rule_enabled"),
		PolicyMonitorReportInternalPolicies: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.policies.monitor.report_internal_policies"),

		LogPatterns: pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.log_patterns"),
		LogTags:     pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.log_tags"),
		EnvAsTags:   pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.env_as_tags"),

		// custom events
		InternalMonitoringEnabled: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.internal_monitoring.enabled"),

		// activity dump
		ActivityDumpEnabled:                   pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.activity_dump.enabled"),
		ActivityDumpCleanupPeriod:             pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.cleanup_period"),
		ActivityDumpTagsResolutionPeriod:      pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.tags_resolution_period"),
		ActivityDumpLoadControlPeriod:         pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.load_controller_period"),
		ActivityDumpLoadControlMinDumpTimeout: pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.min_timeout"),
		ActivityDumpTracedCgroupsCount:        pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.activity_dump.traced_cgroups_count"),
		ActivityDumpCgroupsManagers:           pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.activity_dump.cgroup_managers"),
		ActivityDumpTracedEventTypes:          parseEventTypeStringSlice(pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.activity_dump.traced_event_types")),
		ActivityDumpCgroupDumpTimeout:         pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.dump_duration"),
		ActivityDumpCgroupWaitListTimeout:     pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.cgroup_wait_list_timeout"),
		ActivityDumpCgroupDifferentiateArgs:   pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.activity_dump.cgroup_differentiate_args"),
		ActivityDumpLocalStorageDirectory:     pkgconfigsetup.SystemProbe().GetString("runtime_security_config.activity_dump.local_storage.output_directory"),
		ActivityDumpLocalStorageMaxDumpsCount: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.activity_dump.local_storage.max_dumps_count"),
		ActivityDumpLocalStorageCompression:   pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.activity_dump.local_storage.compression"),
		ActivityDumpSyscallMonitorPeriod:      pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.syscall_monitor.period"),
		ActivityDumpMaxDumpCountPerWorkload:   pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.activity_dump.max_dump_count_per_workload"),
		ActivityDumpTagRulesEnabled:           pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.activity_dump.tag_rules.enabled"),
		ActivityDumpSilentWorkloadsDelay:      pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.silent_workloads.delay"),
		ActivityDumpSilentWorkloadsTicker:     pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.activity_dump.silent_workloads.ticker"),
		ActivityDumpWorkloadDenyList:          pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.activity_dump.workload_deny_list"),
		ActivityDumpAutoSuppressionEnabled:    pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.activity_dump.auto_suppression.enabled"),
		// activity dump dynamic fields
		ActivityDumpMaxDumpSize: func() int {
			mds := max(pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.activity_dump.max_dump_size"), ADMinMaxDumSize)
			return mds * (1 << 10)
		},

		// SBOM resolver
		SBOMResolverEnabled:            pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.sbom.enabled"),
		SBOMResolverWorkloadsCacheSize: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.sbom.workloads_cache_size"),
		SBOMResolverHostEnabled:        pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.sbom.host.enabled"),
		SBOMResolverAnalyzers:          pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.sbom.analyzers"),

		// Hash resolver
		HashResolverEnabled:        pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.hash_resolver.enabled"),
		HashResolverEventTypes:     parseEventTypeStringSlice(pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.hash_resolver.event_types")),
		HashResolverMaxFileSize:    pkgconfigsetup.SystemProbe().GetInt64("runtime_security_config.hash_resolver.max_file_size"),
		HashResolverHashAlgorithms: parseHashAlgorithmStringSlice(pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.hash_resolver.hash_algorithms")),
		HashResolverMaxHashRate:    pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.hash_resolver.max_hash_rate"),
		HashResolverCacheSize:      pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.hash_resolver.cache_size"),
		HashResolverReplace:        pkgconfigsetup.SystemProbe().GetStringMapString("runtime_security_config.hash_resolver.replace"),

		// SysCtl config parameter
		SysCtlEnabled:                        pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.sysctl.enabled"),
		SysCtlSnapshotEnabled:                pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.sysctl.snapshot.enabled"),
		SysCtlSnapshotPeriod:                 pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.sysctl.snapshot.period"),
		SysCtlSnapshotIgnoredBaseNames:       pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.sysctl.snapshot.ignored_base_names"),
		SysCtlSnapshotKernelCompilationFlags: map[string]uint8{},

		// security profiles
		SecurityProfileEnabled:          pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.enabled"),
		SecurityProfileMaxImageTags:     pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.max_image_tags"),
		SecurityProfileDir:              pkgconfigsetup.SystemProbe().GetString("runtime_security_config.security_profile.dir"),
		SecurityProfileWatchDir:         pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.watch_dir"),
		SecurityProfileCacheSize:        pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.cache_size"),
		SecurityProfileMaxCount:         pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.max_count"),
		SecurityProfileDNSMatchMaxDepth: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.dns_match_max_depth"),

		// auto suppression
		SecurityProfileAutoSuppressionEnabled:    pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.auto_suppression.enabled"),
		SecurityProfileAutoSuppressionEventTypes: parseEventTypeStringSlice(pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.security_profile.auto_suppression.event_types")),

		// anomaly detection
		AnomalyDetectionEventTypes:                   parseEventTypeStringSlice(pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.security_profile.anomaly_detection.event_types")),
		AnomalyDetectionDefaultMinimumStablePeriod:   pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.security_profile.anomaly_detection.default_minimum_stable_period"),
		AnomalyDetectionMinimumStablePeriods:         anomalyDetectionMinimumStablePeriods,
		AnomalyDetectionWorkloadWarmupPeriod:         pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.security_profile.anomaly_detection.workload_warmup_period"),
		AnomalyDetectionUnstableProfileTimeThreshold: pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.security_profile.anomaly_detection.unstable_profile_time_threshold"),
		AnomalyDetectionUnstableProfileSizeThreshold: pkgconfigsetup.SystemProbe().GetInt64("runtime_security_config.security_profile.anomaly_detection.unstable_profile_size_threshold"),
		AnomalyDetectionRateLimiterPeriod:            pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.security_profile.anomaly_detection.rate_limiter.period"),
		AnomalyDetectionRateLimiterNumKeys:           pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.anomaly_detection.rate_limiter.num_keys"),
		AnomalyDetectionRateLimiterNumEventsAllowed:  pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.security_profile.anomaly_detection.rate_limiter.num_events_allowed"),
		AnomalyDetectionTagRulesEnabled:              pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.anomaly_detection.tag_rules.enabled"),
		AnomalyDetectionSilentRuleEventsEnabled:      pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.anomaly_detection.silent_rule_events.enabled"),
		AnomalyDetectionEnabled:                      pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.security_profile.anomaly_detection.enabled"),

		// enforcement
		EnforcementEnabled:                      pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.enforcement.enabled"),
		EnforcementBinaryExcluded:               pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.enforcement.exclude_binaries"),
		EnforcementRawSyscallEnabled:            pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.enforcement.raw_syscall.enabled"),
		EnforcementRuleSourceAllowed:            pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.enforcement.rule_source_allowed"),
		EnforcementDisarmerContainerEnabled:     pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.enforcement.disarmer.container.enabled"),
		EnforcementDisarmerContainerMaxAllowed:  pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.enforcement.disarmer.container.max_allowed"),
		EnforcementDisarmerContainerPeriod:      pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.enforcement.disarmer.container.period"),
		EnforcementDisarmerExecutableEnabled:    pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.enforcement.disarmer.executable.enabled"),
		EnforcementDisarmerExecutableMaxAllowed: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.enforcement.disarmer.executable.max_allowed"),
		EnforcementDisarmerExecutablePeriod:     pkgconfigsetup.SystemProbe().GetDuration("runtime_security_config.enforcement.disarmer.executable.period"),

		// User Sessions
		UserSessionsCacheSize: pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.user_sessions.cache_size"),

		// ebpf less
		EBPFLessEnabled: IsEBPFLessModeEnabled(),
		EBPFLessSocket:  pkgconfigsetup.SystemProbe().GetString("runtime_security_config.ebpfless.socket"),

		// IMDS
		IMDSIPv4: parseIMDSIPv4(),

		// direct sender
		SendEventFromSystemProbe: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.direct_send_from_system_probe"),

		// FileMetadataResolverEnabled
		FileMetadataResolverEnabled: pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.file_metadata_resolver.enabled"),
	}

	compilationFlags := pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.sysctl.snapshot.kernel_compilation_flags")
	if len(compilationFlags) == 0 {
		compilationFlags = defaultKernelCompilationFlags
	}
	for _, configFlag := range compilationFlags {
		rsConfig.SysCtlSnapshotKernelCompilationFlags[configFlag] = 1
	}

	activityDumpRateLimiter := pkgconfigsetup.SystemProbe().GetInt("runtime_security_config.activity_dump.rate_limiter")
	if activityDumpRateLimiter < 0 || activityDumpRateLimiter > math.MaxUint16 {
		return nil, fmt.Errorf("invalid value for runtime_security_config.activity_dump.rate_limiter: %d, must be in uint16 range", activityDumpRateLimiter)
	}
	rsConfig.ActivityDumpRateLimiter = uint16(activityDumpRateLimiter)

	if err := rsConfig.sanitize(); err != nil {
		return nil, err
	}

	return rsConfig, nil
}

// IsRuntimeEnabled returns true if any feature is enabled. Has to be applied in config package too
func (c *RuntimeSecurityConfig) IsRuntimeEnabled() bool {
	return c.RuntimeEnabled || c.FIMEnabled
}

// parseIMDSIPv4 returns the uint32 representation of the IMDS IP set by the configuration
func parseIMDSIPv4() uint32 {
	ip := pkgconfigsetup.SystemProbe().GetString("runtime_security_config.imds_ipv4")
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(parsedIP.To4())
}

// If RC is globally enabled, RC is enabled for CWS, unless the CWS-specific RC value is explicitly set to false
func isRemoteConfigEnabled() bool {
	// This value defaults to true
	rcEnabledInSysprobeConfig := pkgconfigsetup.SystemProbe().GetBool("runtime_security_config.remote_configuration.enabled")

	if !rcEnabledInSysprobeConfig {
		return false
	}

	if pkgconfigsetup.IsRemoteConfigEnabled(pkgconfigsetup.Datadog()) {
		return true
	}

	return false
}

// IsEBPFLessModeEnabled returns true if the ebpfless mode is enabled
// it's based on the configuration itself, but will default on true if
// running on fargate
func IsEBPFLessModeEnabled() bool {
	const cfgKey = "runtime_security_config.ebpfless.enabled"
	// by default on fargate, we enable ebpfless mode
	if !pkgconfigsetup.SystemProbe().IsConfigured(cfgKey) && fargate.IsFargateInstance() {
		seclog.Infof("Fargate instance detected, enabling CWS ebpfless mode")
		pkgconfigsetup.SystemProbe().Set(cfgKey, true, pkgconfigmodel.SourceAgentRuntime)
	}

	return pkgconfigsetup.SystemProbe().GetBool(cfgKey)
}

// GetAnomalyDetectionMinimumStablePeriod returns the minimum stable period for a given event type
func (c *RuntimeSecurityConfig) GetAnomalyDetectionMinimumStablePeriod(eventType model.EventType) time.Duration {
	if minimumStablePeriod, found := c.AnomalyDetectionMinimumStablePeriods[eventType]; found {
		return minimumStablePeriod
	}
	return c.AnomalyDetectionDefaultMinimumStablePeriod
}

// sanitize ensures that the configuration is properly setup
func (c *RuntimeSecurityConfig) sanitize() error {
	serviceName := utils.GetTagValue("service", configUtils.GetConfiguredTags(pkgconfigsetup.Datadog(), true))
	if len(serviceName) > 0 {
		c.HostServiceName = serviceName
	}

	if c.IMDSIPv4 == 0 {
		return fmt.Errorf("invalid IPv4 address: got %v", pkgconfigsetup.SystemProbe().GetString("runtime_security_config.imds_ipv4"))
	}

	if c.EnforcementDisarmerContainerEnabled && c.EnforcementDisarmerContainerMaxAllowed <= 0 {
		return fmt.Errorf("invalid value for runtime_security_config.enforcement.disarmer.container.max_allowed: %d", c.EnforcementDisarmerContainerMaxAllowed)
	}

	if c.EnforcementDisarmerExecutableEnabled && c.EnforcementDisarmerExecutableMaxAllowed <= 0 {
		return fmt.Errorf("invalid value for runtime_security_config.enforcement.disarmer.executable.max_allowed: %d", c.EnforcementDisarmerExecutableMaxAllowed)
	}

	c.sanitizePlatform()

	return c.sanitizeRuntimeSecurityConfigActivityDump()
}

// sanitizeRuntimeSecurityConfigActivityDump ensures that runtime_security_config.activity_dump is properly configured
func (c *RuntimeSecurityConfig) sanitizeRuntimeSecurityConfigActivityDump() error {
	if !slices.Contains(c.ActivityDumpTracedEventTypes, model.ExecEventType) {
		c.ActivityDumpTracedEventTypes = append(c.ActivityDumpTracedEventTypes, model.ExecEventType)
	}

	if formats := pkgconfigsetup.SystemProbe().GetStringSlice("runtime_security_config.activity_dump.local_storage.formats"); len(formats) > 0 {
		var err error
		c.ActivityDumpLocalStorageFormats, err = ParseStorageFormats(formats)
		if err != nil {
			return fmt.Errorf("invalid value for runtime_security_config.activity_dump.local_storage.formats: %w", err)
		}
	}

	if c.ActivityDumpTracedCgroupsCount > model.MaxTracedCgroupsCount {
		c.ActivityDumpTracedCgroupsCount = model.MaxTracedCgroupsCount
	}

	if c.SecurityProfileEnabled && c.ActivityDumpEnabled && c.ActivityDumpLocalStorageDirectory != c.SecurityProfileDir {
		return fmt.Errorf("activity dumps storage directory '%s' has to be the same than security profile storage directory '%s'", c.ActivityDumpLocalStorageDirectory, c.SecurityProfileDir)
	}

	return nil
}

// ActivityDumpRemoteStorageEndpoints returns the list of activity dump remote storage endpoints parsed from the agent config
func ActivityDumpRemoteStorageEndpoints(endpointPrefix string, intakeTrackType logsconfig.IntakeTrackType, intakeProtocol logsconfig.IntakeProtocol, intakeOrigin logsconfig.IntakeOrigin) (*logsconfig.Endpoints, error) {
	logsConfig := logsconfig.NewLogsConfigKeys("runtime_security_config.activity_dump.remote_storage.endpoints.", pkgconfigsetup.Datadog())
	endpoints, err := logsconfig.BuildHTTPEndpointsWithConfig(pkgconfigsetup.Datadog(), logsConfig, endpointPrefix, intakeTrackType, intakeProtocol, intakeOrigin)
	if err != nil {
		endpoints, err = logsconfig.BuildHTTPEndpoints(pkgconfigsetup.Datadog(), intakeTrackType, intakeProtocol, intakeOrigin)
		if err == nil {
			httpConnectivity := logshttp.CheckConnectivity(endpoints.Main, pkgconfigsetup.Datadog())
			endpoints, err = logsconfig.BuildEndpoints(pkgconfigsetup.Datadog(), httpConnectivity, intakeTrackType, intakeProtocol, intakeOrigin)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("invalid endpoints: %w", err)
	}

	for _, status := range endpoints.GetStatus() {
		seclog.Infof("activity dump remote storage endpoint: %v\n", status)
	}
	return endpoints, nil
}

// parseEventTypeDurations converts a map of durations indexed by event types
func parseEventTypeDurations(cfg pkgconfigmodel.Config, prefix string) (map[model.EventType]time.Duration, error) {
	eventTypeMap := cfg.GetStringMap(prefix)
	eventTypeDurations := make(map[model.EventType]time.Duration, len(eventTypeMap))
	for eventTypeName := range eventTypeMap {
		eventType, err := model.ParseEvalEventType(eventTypeName)
		if err != nil {
			return nil, err
		}
		eventTypeDurations[eventType] = cfg.GetDuration(prefix + "." + eventTypeName)
	}
	return eventTypeDurations, nil
}

// parseHashAlgorithmStringSlice converts a string list to a list of hash algorithms
func parseHashAlgorithmStringSlice(algorithms []string) []model.HashAlgorithm {
	var output []model.HashAlgorithm
	for _, hashAlgorithm := range algorithms {
		for i := model.HashAlgorithm(0); i < model.MaxHashAlgorithm; i++ {
			if i.String() == hashAlgorithm {
				output = append(output, i)
				break
			}
		}
	}
	return output
}

// GetFamilyAddress returns the address famility to use for system-probe <-> security-agent communication
func GetFamilyAddress(path string) string {
	if strings.HasPrefix(path, "/") {
		return "unix"
	}
	return "tcp"
}
