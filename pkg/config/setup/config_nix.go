// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux || freebsd || netbsd || openbsd || solaris || dragonfly || aix

package setup

import (
	"path/filepath"

	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
)

// Variables to initialize at build time
var (
	// InstallPath is the default install path for the agent
	// It might be overridden at build time
	InstallPath = "/opt/datadog-agent"

	// defaultRunPath is the default run path
	// It is set in osinit to take into account InstallPath overrides
	defaultRunPath = ""
)

var (
	// DefaultSystemProbeAddress is the default unix socket path to be used for connecting to the system probe
	DefaultSystemProbeAddress = filepath.Join(InstallPath, "run/sysprobe.sock")
	// defaultEventMonitorAddress is the default unix socket path to be used for connecting to the event monitor
	defaultEventMonitorAddress = filepath.Join(InstallPath, "run/event-monitor.sock")
	// DefaultDDAgentBin the process agent's binary
	DefaultDDAgentBin = filepath.Join(InstallPath, "bin/agent/agent")
)

const (
	defaultConfdPath            = "/etc/datadog-agent/conf.d"
	defaultAdditionalChecksPath = "/etc/datadog-agent/checks.d"
	defaultGuiPort              = -1
	// DefaultUpdaterLogFile is the default updater log file
	DefaultUpdaterLogFile = "/var/log/datadog/updater.log"
	// DefaultSecurityAgentLogFile points to the log file that will be used by the security-agent if not configured
	DefaultSecurityAgentLogFile = "/var/log/datadog/security-agent.log"
	// DefaultProcessAgentLogFile is the default process-agent log file
	DefaultProcessAgentLogFile = "/var/log/datadog/process-agent.log"
	// DefaultOTelAgentLogFile is the default otel-agent log file
	DefaultOTelAgentLogFile = "/var/log/datadog/otel-agent.log"
	// defaultSystemProbeLogFilePath is the default system-probe log file
	defaultSystemProbeLogFilePath = "/var/log/datadog/system-probe.log"
	// defaultStatsdSocket is the default Unix Domain Socket path on which statsd will listen
	defaultStatsdSocket = "/var/run/datadog/dsd.socket"
	//DefaultStreamlogsLogFile points to the stream logs log file that will be used if not configured
	DefaultStreamlogsLogFile = "/var/log/datadog/streamlogs_info/streamlogs.log"
)

// called by init in config.go, to ensure any os-specific config is done
// in time
func osinit() {
	if defaultRunPath == "" {
		defaultRunPath = filepath.Join(InstallPath, "run")
	}
}

// FleetConfigOverride is a no-op on Linux
func FleetConfigOverride(_ pkgconfigmodel.Config) {
}
