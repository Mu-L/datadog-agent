// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package workloadlist implements 'agent workload-list'.
package workloadlist

import (
	"encoding/json"
	"fmt"
	"net/url"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfigenv "github.com/DataDog/datadog-agent/pkg/config/env"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	GlobalParams

	verboseList bool
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

// MakeCommand returns a `workload-list` command to be used by agent binaries.
func MakeCommand(globalParamsGetter func() GlobalParams) *cobra.Command {
	cliParams := &cliParams{}

	workloadListCommand := &cobra.Command{
		Use:   "workload-list",
		Short: "Print the workload content of a running agent",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			globalParams := globalParamsGetter()

			cliParams.GlobalParams = globalParams

			return fxutil.OneShot(workloadList,
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

	workloadListCommand.Flags().BoolVarP(&cliParams.verboseList, "verbose", "v", false, "print out a full dump of the workload store")

	return workloadListCommand
}

func workloadList(log log.Component, config config.Component, cliParams *cliParams) error {
	c := util.GetClient(false) // FIX: get certificates right then make this true

	// Set session token
	err := util.SetAuthToken()
	if err != nil {
		return err
	}

	url, err := workloadURL(config, cliParams.verboseList)
	if err != nil {
		return err
	}

	r, err := util.DoGet(c, url, util.LeaveConnectionOpen)
	if err != nil {
		if r != nil && string(r) != "" {
			fmt.Fprintf(color.Output, "The agent ran into an error while getting the workload store information: %s\n", string(r))
		} else {
			fmt.Fprintf(color.Output, "Failed to query the agent (running?): %s\n", err)
		}
	}

	workload := workloadmeta.WorkloadDumpResponse{}
	err = json.Unmarshal(r, &workload)
	if err != nil {
		return err
	}

	workload.Write(color.Output)

	return nil
}

func workloadURL(config config.Component, verbose bool) (string, error) {
	var url *url.URL
	var err error
	if flavor.GetFlavor() == flavor.ClusterAgent {
		url, err = pkgconfigenv.GetIPCURL(config, "https", "cluster_agent.cmd_port", "/workload-list")
	} else {
		url, err = pkgconfigenv.GetIPCURL(config, "https", "cmd_port", "/agent/workload-list")
	}
	if err != nil {
		return "", err
	}

	if verbose {
		url.RawQuery = "verbose=true"
	}

	return url.String(), nil
}
