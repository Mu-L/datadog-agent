// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package taggerlist implements 'agent tagger-list'.
package taggerlist

import (
	"fmt"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipcfx "github.com/DataDog/datadog-agent/comp/core/ipc/fx"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/api"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	GlobalParams
}

// GlobalParams contains the values of agent-global Cobra flags.
//
// A pointer to this type is passed to SubcommandFactory's, but its contents
// are not valid until Cobra calls the subcommand's Run or RunE function.
type GlobalParams struct {
	ConfFilePath         string
	ExtraConfFilePaths   []string
	ConfigName           string
	LoggerName           string
	FleetPoliciesDirPath string
}

// MakeCommand returns a `tagger-list` command to be used by agent binaries.
func MakeCommand(globalParamsGetter func() GlobalParams) *cobra.Command {
	cliParams := &cliParams{}

	return &cobra.Command{
		Use:   "tagger-list",
		Short: "Print the tagger content of a running agent",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			globalParams := globalParamsGetter()

			cliParams.GlobalParams = globalParams

			return fxutil.OneShot(taggerList,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParams(
						globalParams.ConfFilePath,
						config.WithConfigName(globalParams.ConfigName),
						config.WithExtraConfFiles(globalParams.ExtraConfFilePaths),
						config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath),
					),
					LogParams: log.ForOneShot(globalParams.LoggerName, "off", true)}),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}
}

func taggerList(_ log.Component, config config.Component, client ipc.HTTPClient, _ *cliParams) error {
	url, err := getTaggerURL(config)
	if err != nil {
		return err
	}

	return api.GetTaggerList(client, color.Output, url)
}

func getTaggerURL(config config.Component) (string, error) {
	ipcAddress, err := pkgconfigsetup.GetIPCAddress(config)
	if err != nil {
		return "", err
	}

	var urlstr string
	if flavor.GetFlavor() == flavor.ClusterAgent {
		urlstr = fmt.Sprintf("https://%v:%v/tagger-list", ipcAddress, config.GetInt("cluster_agent.cmd_port"))
	} else {
		urlstr = fmt.Sprintf("https://%v:%v/agent/tagger-list", ipcAddress, config.GetInt("cmd_port"))
	}

	return urlstr, nil
}
