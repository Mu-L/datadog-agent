// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package noopautoconfig provides a noop implementation for the autodiscovery component
package noopautoconfig

import (
	"context"
	"time"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/providers/types"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/scheduler"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/telemetry"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(
			newAutoConfig,
		),
	)
}

type noopAutoConfig struct{}

func (n *noopAutoConfig) AddConfigProvider(types.ConfigProvider, bool, time.Duration) {}

func (n *noopAutoConfig) LoadAndRun(context.Context) {}

func (n *noopAutoConfig) GetAllConfigs() []integration.Config {
	return []integration.Config{}
}

func (n *noopAutoConfig) AddListeners([]pkgconfigsetup.Listeners) {}

func (n *noopAutoConfig) AddScheduler(string, scheduler.Scheduler, bool) {}

func (n *noopAutoConfig) RemoveScheduler(string) {}

func (n *noopAutoConfig) GetIDOfCheckWithEncryptedSecrets(checkid.ID) checkid.ID {
	return ""
}

func (n *noopAutoConfig) GetAutodiscoveryErrors() map[string]map[string]types.ErrorMsgSet {
	return map[string]map[string]types.ErrorMsgSet{}
}

func (n *noopAutoConfig) GetProviderCatalog() map[string]types.ConfigProviderFactory {
	return map[string]types.ConfigProviderFactory{}
}

func (n *noopAutoConfig) GetTelemetryStore() *telemetry.Store {
	return nil
}

func (n *noopAutoConfig) GetConfigCheck() integration.ConfigCheckResponse {
	return integration.ConfigCheckResponse{}
}

func newAutoConfig() autodiscovery.Component {
	return &noopAutoConfig{}
}
