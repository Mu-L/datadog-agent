// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

// Package middleware contains a check wrapper helper
package middleware

import (
	"fmt"
	"sync"
	"time"

	agenttelemetry "github.com/DataDog/datadog-agent/comp/core/agenttelemetry/def"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	diagnose "github.com/DataDog/datadog-agent/comp/core/diagnose/def"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	"github.com/DataDog/datadog-agent/pkg/collector/check/stats"
	"github.com/DataDog/datadog-agent/pkg/util/option"
)

// CheckWrapper cleans up the check sender after a check was
// descheduled, taking care that Run is not executing during or after
// that.
type CheckWrapper struct {
	senderManager  sender.SenderManager
	agentTelemetry option.Option[agenttelemetry.Component]

	inner check.Check
	// done is true when the check was cancelled and must not run.
	done bool
	// Locked while check is running.
	runM sync.Mutex
}

// NewCheckWrapper returns a wrapped check.
func NewCheckWrapper(inner check.Check, senderManager sender.SenderManager, agentTelemetry option.Option[agenttelemetry.Component]) *CheckWrapper {
	return &CheckWrapper{
		inner:          inner,
		senderManager:  senderManager,
		agentTelemetry: agentTelemetry,
	}
}

// Run implements Check#Run
func (c *CheckWrapper) Run() (err error) {
	c.runM.Lock()
	defer c.runM.Unlock()
	if c.done {
		return nil
	}

	// Start telemetry span if telemetry is enabled
	if telemetry, isSet := c.agentTelemetry.Get(); isSet {
		span, _ := telemetry.StartStartupSpan(fmt.Sprintf("check.%s", c.inner.String()))
		defer span.Finish(err)
	}

	// Run the check
	return c.inner.Run()
}

// Cancel implements Check#Cancel
func (c *CheckWrapper) Cancel() {
	c.inner.Cancel()
	go c.destroySender()
}

func (c *CheckWrapper) destroySender() {
	// Done must happen before Wait
	c.runM.Lock()
	defer c.runM.Unlock()
	c.done = true
	c.senderManager.DestroySender(c.ID())
}

// Stop implements Check#Stop
func (c *CheckWrapper) Stop() {
	c.inner.Stop()
}

// String implements Check#String
func (c *CheckWrapper) String() string {
	return c.inner.String()
}

// Configure implements Check#Configure
func (c *CheckWrapper) Configure(senderManager sender.SenderManager, integrationConfigDigest uint64, config, initConfig integration.Data, source string) error {
	if c.senderManager == nil {
		c.senderManager = senderManager
	}
	return c.inner.Configure(c.senderManager, integrationConfigDigest, config, initConfig, source)
}

// Interval implements Check#Interval
func (c *CheckWrapper) Interval() time.Duration {
	return c.inner.Interval()
}

// ID implements Check#ID
func (c *CheckWrapper) ID() checkid.ID {
	return c.inner.ID()
}

// GetWarnings implements Check#GetWarnings
func (c *CheckWrapper) GetWarnings() []error {
	return c.inner.GetWarnings()
}

// GetSenderStats implements Check#GetSenderStats
func (c *CheckWrapper) GetSenderStats() (stats.SenderStats, error) {
	return c.inner.GetSenderStats()
}

// Version implements Check#Version
func (c *CheckWrapper) Version() string {
	return c.inner.Version()
}

// ConfigSource implements Check#ConfigSource
func (c *CheckWrapper) ConfigSource() string {
	return c.inner.ConfigSource()
}

// Loader returns the name of the check loader
func (c *CheckWrapper) Loader() string {
	return c.inner.Loader()
}

// IsTelemetryEnabled implements Check#IsTelemetryEnabled
func (c *CheckWrapper) IsTelemetryEnabled() bool {
	return c.inner.IsTelemetryEnabled()
}

// InitConfig implements Check#InitConfig
func (c *CheckWrapper) InitConfig() string {
	return c.inner.InitConfig()
}

// InstanceConfig implements Check#InstanceConfig
func (c *CheckWrapper) InstanceConfig() string {
	return c.inner.InstanceConfig()
}

// GetDiagnoses returns the diagnoses cached in last run or diagnose explicitly
func (c *CheckWrapper) GetDiagnoses() ([]diagnose.Diagnosis, error) {
	// Avoid running concurrently with Run method (for now)
	c.runM.Lock()
	defer c.runM.Unlock()

	if c.done {
		return nil, nil
	}
	return c.inner.GetDiagnoses()
}

// IsHASupported implements Check#IsHASupported
func (c *CheckWrapper) IsHASupported() bool {
	return c.inner.IsHASupported()
}
