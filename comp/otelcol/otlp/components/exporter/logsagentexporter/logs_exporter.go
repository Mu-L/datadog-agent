// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

package logsagentexporter

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/util/otel"
	"github.com/DataDog/datadog-agent/pkg/util/scrubber"

	"github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/attributes"
	logsmapping "github.com/DataDog/opentelemetry-mapping-go/pkg/otlp/logs"
	"github.com/stormcat24/protodep/pkg/logger"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Exporter defines fields for the logs agent exporter
type Exporter struct {
	set              component.TelemetrySettings
	logsAgentChannel chan *message.Message
	logSource        *sources.LogSource
	translator       *logsmapping.Translator
	gatewaysUsage    otel.GatewayUsage
}

// NewExporter initializes a new logs agent exporter with the given parameters
func NewExporter(
	set component.TelemetrySettings,
	cfg *Config,
	logSource *sources.LogSource,
	logsAgentChannel chan *message.Message,
	attributesTranslator *attributes.Translator,
) (*Exporter, error) {
	return NewExporterWithGatewayUsage(set, cfg, logSource, logsAgentChannel, attributesTranslator, otel.NewDisabledGatewayUsage())
}

// NewExporterWithGatewayUsage initializes a new logs agent exporter with the given parameters
func NewExporterWithGatewayUsage(
	set component.TelemetrySettings,
	cfg *Config,
	logSource *sources.LogSource,
	logsAgentChannel chan *message.Message,
	attributesTranslator *attributes.Translator,
	gatewaysUsage otel.GatewayUsage,
) (*Exporter, error) {
	translator, err := logsmapping.NewTranslator(set, attributesTranslator, cfg.OtelSource)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		set:              set,
		logsAgentChannel: logsAgentChannel,
		logSource:        logSource,
		translator:       translator,
		gatewaysUsage:    gatewaysUsage,
	}, nil
}

// ConsumeLogs maps logs from OTLP to DD format and ingests them through the exporter channel
func (e *Exporter) ConsumeLogs(ctx context.Context, ld plog.Logs) (err error) {
	defer func() {
		if err != nil {
			newErr, scrubbingErr := scrubber.ScrubString(err.Error())
			if scrubbingErr != nil {
				err = scrubbingErr
			} else {
				err = errors.New(newErr)
			}
		}
	}()

	payloads := e.translator.MapLogs(ctx, ld, e.gatewaysUsage.GetHostFromAttributesHandler())
	for _, ddLog := range payloads {
		tags := strings.Split(ddLog.GetDdtags(), ",")
		// Tags are set in the message origin instead
		ddLog.Ddtags = nil
		service := ""
		if ddLog.Service != nil {
			service = *ddLog.Service
		}
		status := message.StatusInfo
		if val, ok := ddLog.AdditionalProperties["status"]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				status = strVal
			}
		}
		origin := message.NewOrigin(e.logSource)
		origin.SetTags(tags)
		origin.SetService(service)
		src := e.logSource.Name
		if val, ok := ddLog.AdditionalProperties["datadog.log.source"]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				src = strVal
			}
		}
		origin.SetSource(src)

		content, err := ddLog.MarshalJSON()
		if err != nil {
			logger.Error("Error parsing log: " + err.Error())
		}

		// ingestionTs is an internal field used for latency tracking on the status page, not the actual log timestamp.
		ingestionTs := time.Now().UnixNano()
		message := message.NewMessage(content, origin, status, ingestionTs)
		if ddLog.Hostname != nil {
			message.Hostname = *ddLog.Hostname
		}

		e.logsAgentChannel <- message
	}

	return nil
}
