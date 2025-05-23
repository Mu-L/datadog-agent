// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

// Package demultiplexer defines the aggregator demultiplexer
package demultiplexer

import (
	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/serializer"
)

// team: agent-metric-pipelines

// Component is the component type.
type Component interface {
	sender.SenderManager

	// TODO: (components) remove this method once the serializer is a component
	Serializer() serializer.MetricSerializer

	aggregator.DemultiplexerWithAggregator

	// AddAgentStartupTelemetry adds a startup event and count (in a DSD time sampler)
	// to be sent on the next flush.
	AddAgentStartupTelemetry(agentVersion string)

	sender.DiagnoseSenderManager
}
