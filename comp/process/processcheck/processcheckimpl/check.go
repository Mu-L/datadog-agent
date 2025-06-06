// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package processcheckimpl implements a component to handle Process data collection in the Process Agent.
package processcheckimpl

import (
	"github.com/DataDog/datadog-go/v5/statsd"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	"github.com/DataDog/datadog-agent/comp/core/sysprobeconfig"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	gpusubscriber "github.com/DataDog/datadog-agent/comp/process/gpusubscriber/def"
	"github.com/DataDog/datadog-agent/comp/process/processcheck"
	"github.com/DataDog/datadog-agent/comp/process/types"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fx.Provide(newCheck))
}

var _ types.CheckComponent = (*check)(nil)

type check struct {
	processCheck *checks.ProcessCheck
}

type dependencies struct {
	fx.In

	Config        config.Component
	Sysconfig     sysprobeconfig.Component
	WMmeta        workloadmeta.Component
	GpuSubscriber gpusubscriber.Component
	Statsd        statsd.ClientInterface
	IPC           ipc.Component
}

type result struct {
	fx.Out

	Check     types.ProvidesCheck
	Component processcheck.Component
}

func newCheck(deps dependencies) result {
	c := &check{
		processCheck: checks.NewProcessCheck(deps.Config, deps.Sysconfig, deps.WMmeta, deps.GpuSubscriber, deps.Statsd, deps.IPC.GetTLSServerConfig()),
	}
	return result{
		Check: types.ProvidesCheck{
			CheckComponent: c,
		},
		Component: c,
	}
}

func (c *check) Object() checks.Check {
	return c.processCheck
}
