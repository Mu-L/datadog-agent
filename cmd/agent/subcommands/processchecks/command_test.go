// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package processchecks

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/cmd/process-agent/subcommands/check"
	ipcmock "github.com/DataDog/datadog-agent/comp/core/ipc/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestCommand(t *testing.T) {
	fxutil.TestOneShotSubcommand(t,
		Commands(newGlobalParamsTest(t)),
		[]string{"processchecks", "process"},
		check.RunCheckCmd,
		func(_ *check.CliParams) {},
	)
}

func newGlobalParamsTest(t *testing.T) *command.GlobalParams {
	testDir := t.TempDir()

	configPath := path.Join(testDir, "datadog.yaml")

	// creating in-memory auth artifacts
	ipcmock.New(t)

	err := os.WriteFile(configPath, []byte("hostname: test"), 0644)
	require.NoError(t, err)

	return &command.GlobalParams{
		ConfFilePath: configPath,
	}
}
