// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package taggerlist implements 'agent tagger-list'.
package taggerlist

import (
	"net/url"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfigenv "github.com/DataDog/datadog-agent/pkg/config/env"
	tagger_api "github.com/DataDog/datadog-agent/pkg/tagger/api"
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
	ConfFilePath string
	ConfigName   string
	LoggerName   string
}

// MakeCommand returns a `tagger-list` command to be used by agent binaries.
func MakeCommand(globalParamsGetter func() GlobalParams) *cobra.Command {
	cliParams := &cliParams{}

	return &cobra.Command{
		Use:   "tagger-list",
		Short: "Print the tagger content of a running agent",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			globalParams := globalParamsGetter()

			cliParams.GlobalParams = globalParams

			return fxutil.OneShot(taggerList,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewAgentParamsWithoutSecrets(
						globalParams.ConfFilePath,
						config.WithConfigName(globalParams.ConfigName),
					),
					LogParams: log.ForOneShot(globalParams.LoggerName, "off", true)}),
				core.Bundle,
			)
		},
	}
}

func taggerList(log log.Component, config config.Component, cliParams *cliParams) error {
	// Set session token
	if err := util.SetAuthToken(); err != nil {
		return err
	}

	url, err := getTaggerURL(config)
	if err != nil {
		return err
	}

	return tagger_api.GetTaggerList(color.Output, url)
}

func getTaggerURL(config config.Component) (string, error) {
	var url *url.URL
	var err error
	if flavor.GetFlavor() == flavor.ClusterAgent {
		url, err = pkgconfigenv.GetIPCURL(config, "https", "cluster_agent.cmd_port", "/tagger-list")
	} else {
		url, err = pkgconfigenv.GetIPCURL(config, "https", "cmd_port", "/agent/tagger-list")
	}
	if err != nil {
		return "", err
	}

	return url.String(), nil
}
