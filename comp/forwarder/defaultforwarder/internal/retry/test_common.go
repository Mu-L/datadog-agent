// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build test

package retry

import "github.com/DataDog/datadog-agent/pkg/telemetry"

//nolint:revive // TODO(ASC) Fix revive linter
func NewPointCountTelemetryMock() *PointCountTelemetry {
	provider := telemetry.NewStatsTelemetryProvider(StatsTelemetrySenderMock{})
	return NewPointCountTelemetry("domain", provider)
}

//nolint:revive // TODO(ASC) Fix revive linter
type StatsTelemetrySenderMock struct{}

//nolint:revive // TODO(ASC) Fix revive linter
func (m StatsTelemetrySenderMock) Count(metric string, value float64, hostname string, tags []string) {
}

//nolint:revive // TODO(ASC) Fix revive linter
func (m StatsTelemetrySenderMock) Gauge(metric string, value float64, hostname string, tags []string) {
}

//nolint:revive // TODO(ASC) Fix revive linter
func (m StatsTelemetrySenderMock) GaugeNoIndex(metric string, value float64, hostname string, tags []string) {
}
