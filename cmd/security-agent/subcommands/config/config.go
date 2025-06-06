// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package config holds config related files
package config

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/security-agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipcfx "github.com/DataDog/datadog-agent/comp/core/ipc/fx"
	ipchttp "github.com/DataDog/datadog-agent/comp/core/ipc/httphelpers"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/pkg/config/fetcher"
	"github.com/DataDog/datadog-agent/pkg/config/settings"
	settingshttp "github.com/DataDog/datadog-agent/pkg/config/settings/http"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type cliParams struct {
	*command.GlobalParams

	command *cobra.Command
	args    []string
}

// Commands returns the config commands
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	cliParams := &cliParams{
		GlobalParams: globalParams,
	}

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Print the runtime configuration of a running agent",
		Long:  ``,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cliParams.command = cmd
			cliParams.args = args
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return fxutil.OneShot(
				showRuntimeConfiguration,
				fx.Supply(cliParams),
				fx.Supply(core.BundleParams{
					ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths, config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
					SecretParams: secrets.NewEnabledParams(),
					LogParams:    log.ForOneShot(command.LoggerName, "off", true)}),
				core.Bundle(),
				ipcfx.ModuleReadOnly(),
			)
		},
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "by-source",
			Short: "Show the runtime configuration by source (ie: default, config file, env vars, ...)",
			Long:  ``,
			RunE: func(_ *cobra.Command, _ []string) error {
				return fxutil.OneShot(
					showRuntimeConfigurationBySource,
					fx.Supply(cliParams),
					fx.Supply(core.BundleParams{
						ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths, config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
						SecretParams: secrets.NewEnabledParams(),
						LogParams:    log.ForOneShot(command.LoggerName, "off", true)}),
					core.Bundle(),
					ipcfx.ModuleReadOnly(),
				)
			},
		},
	)

	// listRuntime returns a cobra command to list the settings that can be changed at runtime.
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list-runtime",
			Short: "List settings that can be changed at runtime",
			Long:  ``,
			RunE: func(_ *cobra.Command, _ []string) error {
				return fxutil.OneShot(
					listRuntimeConfigurableValue,
					fx.Supply(cliParams),
					fx.Supply(core.BundleParams{
						ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths, config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
						SecretParams: secrets.NewEnabledParams(),
						LogParams:    log.ForOneShot(command.LoggerName, "off", true)}),
					core.Bundle(),
					ipcfx.ModuleReadOnly(),
				)
			},
		},
	)

	// set returns a cobra command to set a config value at runtime.
	cmd.AddCommand(
		&cobra.Command{
			Use:   "set [setting] [value]",
			Short: "Set, for the current runtime, the value of a given configuration setting",
			Long:  ``,
			RunE: func(_ *cobra.Command, _ []string) error {
				return fxutil.OneShot(
					setConfigValue,
					fx.Supply(cliParams),
					fx.Supply(core.BundleParams{
						ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths, config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
						SecretParams: secrets.NewEnabledParams(),
						LogParams:    log.ForOneShot(command.LoggerName, "off", true)}),
					core.Bundle(),
					ipcfx.ModuleReadOnly(),
				)
			},
		},
	)

	// get returns a cobra command to get a runtime config value.
	cmd.AddCommand(
		&cobra.Command{
			Use:   "get [setting]",
			Short: "Get, for the current runtime, the value of a given configuration setting",
			Long:  ``,
			RunE: func(_ *cobra.Command, _ []string) error {
				return fxutil.OneShot(
					getConfigValue,
					fx.Supply(cliParams),
					fx.Supply(core.BundleParams{
						ConfigParams: config.NewSecurityAgentParams(globalParams.ConfigFilePaths, config.WithFleetPoliciesDirPath(globalParams.FleetPoliciesDirPath)),
						SecretParams: secrets.NewEnabledParams(),
						LogParams:    log.ForOneShot(command.LoggerName, "off", true)}),
					core.Bundle(),
					ipcfx.ModuleReadOnly(),
				)
			},
		},
	)

	return []*cobra.Command{cmd}
}
func getSettingsClient(client ipc.HTTPClient) (settings.Client, error) {
	apiConfigURL := fmt.Sprintf("https://localhost:%v/agent/config", pkgconfigsetup.Datadog().GetInt("security_agent.cmd_port"))

	return settingshttp.NewHTTPSClient(client, apiConfigURL, "security-agent", ipchttp.WithLeaveConnectionOpen), nil
}

func showRuntimeConfiguration(_ log.Component, cfg config.Component, _ secrets.Component, _ *cliParams, client ipc.HTTPClient) error {
	runtimeConfig, err := fetcher.SecurityAgentConfig(cfg, client)
	if err != nil {
		return err
	}

	fmt.Println(runtimeConfig)
	return nil
}

func setConfigValue(_ log.Component, _ config.Component, _ secrets.Component, client ipc.HTTPClient, params *cliParams) error {
	if len(params.args) != 2 {
		return fmt.Errorf("exactly two parameters are required: the setting name and its value")
	}

	c, err := getSettingsClient(client)
	if err != nil {
		return err
	}

	hidden, err := c.Set(params.args[0], params.args[1])
	if err != nil {
		return err
	}

	if hidden {
		fmt.Printf("IMPORTANT: you have modified a hidden option, this may incur billing charges or have other unexpected side-effects.\n")
	}

	fmt.Printf("Configuration setting %s is now set to: %s\n", params.args[0], params.args[1])

	return nil
}

func getConfigValue(_ log.Component, _ config.Component, _ secrets.Component, client ipc.HTTPClient, params *cliParams) error {
	if len(params.args) != 1 {
		return fmt.Errorf("a single setting name must be specified")
	}

	c, err := getSettingsClient(client)
	if err != nil {
		return err
	}

	value, err := c.Get(params.args[0])
	if err != nil {
		return err
	}

	fmt.Printf("%s is set to: %v\n", params.args[0], value)

	return nil
}

func showRuntimeConfigurationBySource(_ log.Component, _ secrets.Component, client ipc.HTTPClient, _ *cliParams) error {
	c, err := getSettingsClient(client)
	if err != nil {
		return err
	}

	config, err := c.FullConfigBySource()
	if err != nil {
		return err
	}

	fmt.Println(config)

	return nil
}

func listRuntimeConfigurableValue(_ log.Component, _ secrets.Component, client ipc.HTTPClient, _ *cliParams) error {
	c, err := getSettingsClient(client)
	if err != nil {
		return err
	}

	settingsList, err := c.List()
	if err != nil {
		return err
	}

	fmt.Println("=== Settings that can be changed at runtime ===")
	for setting, details := range settingsList {
		if !details.Hidden {
			fmt.Printf("%-30s %s\n", setting, details.Description)
		}
	}

	return nil
}
