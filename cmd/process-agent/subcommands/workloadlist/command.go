// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO(PROC) Fix revive linter
package workloadlist

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/process-agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipcfx "github.com/DataDog/datadog-agent/comp/core/ipc/fx"
	ipchttp "github.com/DataDog/datadog-agent/comp/core/ipc/httphelpers"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type cliParams struct {
	*command.GlobalParams
	verboseList bool
}

// Commands returns a slice of subcommands for the `workload-list` command in the Process Agent
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &cliParams{
		GlobalParams: globalParams,
	}
	workloadListCommand := &cobra.Command{
		Use:   "workload-list",
		Short: "Print the workload content of a running agent",
		Long:  ``,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fxutil.OneShot(workloadList,
				fx.Supply(cliParams),
				fx.Supply(command.GetCoreBundleParamsForOneShot(globalParams)),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}
	workloadListCommand.Flags().BoolVarP(&cliParams.verboseList, "verbose", "", false, "print out a full dump of the workload store")

	return []*cobra.Command{workloadListCommand}
}

func workloadList(_ log.Component, config config.Component, client ipc.HTTPClient, cliParams *cliParams) error {
	url, err := workloadURL(cliParams.verboseList)
	if err != nil {
		return err
	}

	r, err := client.Get(url, ipchttp.WithLeaveConnectionOpen)
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

func workloadURL(verbose bool) (string, error) {
	addressPort, err := pkgconfigsetup.GetProcessAPIAddressPort(pkgconfigsetup.Datadog())
	if err != nil {
		return "", fmt.Errorf("config error: %s", err.Error())
	}

	url := fmt.Sprintf("https://%s/agent/workload-list", addressPort)

	if verbose {
		return url + "/verbose", nil
	}

	return url + "/short", nil
}
