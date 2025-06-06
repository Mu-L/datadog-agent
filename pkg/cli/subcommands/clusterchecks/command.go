// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package clusterchecks builds a 'clusterchecks' command to be used in binaries.
package clusterchecks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipcfx "github.com/DataDog/datadog-agent/comp/core/ipc/fx"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	clusterAgentFlare "github.com/DataDog/datadog-agent/pkg/flare/clusteragent"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

const (
	loggerName      = "CLUSTER"
	defaultLogLevel = "off"
)

// GlobalParams contains the values of agent-global Cobra flags.
//
// A pointer to this type is passed to SubcommandFactory's, but its contents
// are not valid until Cobra calls the subcommand's Run or RunE function.
type GlobalParams struct {
	ConfFilePath string
}

type cliParams struct {
	GlobalParams

	checkName string
	force     bool
	checkID   string
}

// MakeCommand returns a `clusterchecks` command to be used by cluster-agent
// binaries.
func MakeCommand(globalParamsGetter func() GlobalParams) *cobra.Command {
	cliParams := &cliParams{}

	cmd := &cobra.Command{
		Use:   "clusterchecks",
		Short: "Prints the active cluster check configurations",
		Long:  ``,
		RunE: func(*cobra.Command, []string) error {
			globalParams := globalParamsGetter()

			return fxutil.OneShot(run,
				fx.Supply(cliParams),
				fx.Supply(bundleParams(globalParams)),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}

	cmd.Flags().StringVarP(&cliParams.checkName, "check", "", "", "the check name to filter for")

	rebalanceCmd := &cobra.Command{
		Use:   "rebalance",
		Short: "Rebalances cluster checks",
		Long:  ``,
		RunE: func(*cobra.Command, []string) error {
			globalParams := globalParamsGetter()

			return fxutil.OneShot(rebalance,
				fx.Supply(cliParams),
				fx.Supply(bundleParams(globalParams)),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}

	rebalanceCmd.Flags().BoolVarP(&cliParams.force, "force", "f", false, "Use to force rebalance")

	cmd.AddCommand(rebalanceCmd)

	isolateCmd := &cobra.Command{
		Use:   "isolate",
		Short: "Isolates a single check in the cluster runner",
		Long:  ``,
		RunE: func(*cobra.Command, []string) error {
			globalParams := globalParamsGetter()

			return fxutil.OneShot(isolate,
				fx.Supply(cliParams),
				fx.Supply(bundleParams(globalParams)),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}
	isolateCmd.Flags().StringVarP(&cliParams.checkID, "checkID", "", "", "the check ID to isolate")
	cmd.AddCommand(isolateCmd)

	return cmd
}

func bundleParams(globalParams GlobalParams) core.BundleParams {
	return core.BundleParams{
		ConfigParams: config.NewClusterAgentParams(globalParams.ConfFilePath),
		SecretParams: secrets.NewEnabledParams(),
		LogParams:    log.ForOneShot(loggerName, defaultLogLevel, true),
	}
}

//nolint:revive // TODO(CINT) Fix revive linter
func run(_ log.Component, _ config.Component, cliParams *cliParams, client ipc.HTTPClient) error {
	if err := clusterAgentFlare.GetClusterChecks(color.Output, cliParams.checkName, client); err != nil {
		return err
	}

	return clusterAgentFlare.GetEndpointsChecks(color.Output, cliParams.checkName, client)
}

func rebalance(_ log.Component, client ipc.HTTPClient, cliParams *cliParams) error {
	fmt.Println("Requesting a cluster check rebalance...")
	urlstr := fmt.Sprintf("https://localhost:%v/api/v1/clusterchecks/rebalance", pkgconfigsetup.Datadog().GetInt("cluster_agent.cmd_port"))

	// Construct the POST payload.
	payload := map[string]bool{
		"force": cliParams.force,
	}
	postData, err := json.Marshal(payload)

	if err != nil {
		return fmt.Errorf("error marshalling payload: %v", err)
	}

	r, err := client.Post(urlstr, "application/json", bytes.NewBuffer(postData))
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap) //nolint:errcheck
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			err = errors.New(e)
		}

		fmt.Printf(`
		Could not reach agent: %v
		Make sure the agent is running before requesting the cluster checks rebalancing.
		Contact support if you continue having issues.`, err)

		return err
	}

	checksMoved := make([]types.RebalanceResponse, 0)
	json.Unmarshal(r, &checksMoved) //nolint:errcheck

	fmt.Printf("%d cluster checks rebalanced successfully\n", len(checksMoved))

	for _, check := range checksMoved {
		fmt.Printf("Check %s with weight %d moved from node %s to %s. source diff: %d, dest diff: %d\n",
			check.CheckID, check.CheckWeight, check.SourceNodeName, check.DestNodeName, check.SourceDiff, check.DestDiff)
	}

	return nil
}

func isolate(_ log.Component, client ipc.HTTPClient, cliParams *cliParams) error {
	if cliParams.checkID == "" {
		return fmt.Errorf("checkID must be specified")
	}
	urlstr := fmt.Sprintf("https://localhost:%v/api/v1/clusterchecks/isolate/check/%s", pkgconfigsetup.Datadog().GetInt("cluster_agent.cmd_port"), cliParams.checkID)

	r, err := client.Post(urlstr, "application/json", bytes.NewBuffer([]byte{}))
	if err != nil {
		var errMap = make(map[string]string)
		json.Unmarshal(r, &errMap) //nolint:errcheck
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			err = errors.New(e)
		}

		fmt.Printf(`
		Could not reach agent: %v
		Make sure the agent is running before requesting to isolate a cluster check.
		Contact support if you continue having issues.`, err)

		return err
	}

	var response types.IsolateResponse

	json.Unmarshal(r, &response) //nolint:errcheck
	if response.IsIsolated {
		fmt.Printf("Check %s isolated successfully on node %s\n", response.CheckID, response.CheckNode)
	} else {
		fmt.Printf("Check %s could not be isolated: %s\n", response.CheckID, response.Reason)
	}
	return nil
}
