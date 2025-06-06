// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package fx provides the fx module for the daemonchecker component
package fx

import (
	daemonchecker "github.com/DataDog/datadog-agent/comp/updater/daemonchecker/def"
	daemoncheckerimpl "github.com/DataDog/datadog-agent/comp/updater/daemonchecker/impl"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component
func Module() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(
			daemoncheckerimpl.NewComponent,
		),
		fxutil.ProvideOptional[daemonchecker.Component](),
	)
}
