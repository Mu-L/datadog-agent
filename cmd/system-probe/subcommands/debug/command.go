// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package debug is the debug system-probe subcommand
package debug

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/system-probe/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/sysprobeconfig"
	"github.com/DataDog/datadog-agent/comp/core/sysprobeconfig/sysprobeconfigimpl"
	"github.com/DataDog/datadog-agent/pkg/system-probe/api/client"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// cliParams are the command-line arguments for this subcommand
type cliParams struct {
	*command.GlobalParams

	// args contains the positional command-line arguments
	args []string
}

// Commands returns a slice of subcommands for the 'agent' command.
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &cliParams{
		GlobalParams: globalParams,
	}
	debugCommand := &cobra.Command{
		Use:   "debug [module] [state]",
		Short: "Print the runtime state of a running system-probe",
		Long:  ``,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cliParams.args = args
			return fxutil.OneShot(debugRuntime,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams:         config.NewAgentParams("", config.WithConfigMissingOK(true)),
					SysprobeConfigParams: sysprobeconfigimpl.NewParams(sysprobeconfigimpl.WithSysProbeConfFilePath(globalParams.ConfFilePath), sysprobeconfigimpl.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
					LogParams:            log.ForOneShot("SYS-PROBE", "off", false),
				}),
				// no need to provide sysprobe logger since ForOneShot ignores config values
				core.Bundle(),
			)
		},
	}

	return []*cobra.Command{debugCommand}
}

func debugRuntime(sysprobeconfig sysprobeconfig.Component, cliParams *cliParams) error {
	cfg := sysprobeconfig.SysProbeObject()
	client := client.Get(cfg.SocketAddress)

	var path string
	if len(cliParams.args) == 1 {
		path = fmt.Sprintf("http://localhost/debug/%s", cliParams.args[0])
	} else {
		path = fmt.Sprintf("http://localhost/%s/debug/%s", cliParams.args[0], cliParams.args[1])
	}

	// TODO rather than allowing arbitrary query params, use cobra flags
	r, err := client.Get(path)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(r.Body)
	r.Body.Close()

	if err != nil {
		var errMap = make(map[string]string)
		_ = json.Unmarshal(body, &errMap)
		// If the error has been marshalled into a json object, check it and return it properly
		if e, found := errMap["error"]; found {
			return errors.New(e)
		}

		return fmt.Errorf("Could not reach system-probe: %s\nMake sure system-probe is running before running this command and contact support if you continue having issues", err)
	}

	s, err := strconv.Unquote(string(body))
	if err != nil {
		fmt.Println(string(body))
		return nil
	}
	fmt.Println(s)
	return nil
}
