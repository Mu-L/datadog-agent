// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestComplianceModuleNoProcess(t *testing.T) {
	{
		url := "/dbconfig"
		statusCode, _, respBody := doDBConfigRequest(t, url)
		require.Contains(t, string(respBody), "pid query parameter is not an integer")
		require.Equal(t, http.StatusBadRequest, statusCode)
	}

	{
		url := "/dbconfig?pid=0"
		statusCode, _, respBody := doDBConfigRequest(t, url)
		require.Contains(t, "resource not found for pid=0", string(respBody))
		require.Equal(t, http.StatusNotFound, statusCode)
	}
}

func TestComplianceCheckModuleWithProcess(t *testing.T) {
	tmp := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pid := launchFakeProcess(ctx, t, tmp, "postgres")
	url := fmt.Sprintf("/dbconfig?pid=%d", pid)
	statusCode, _, respBody := doDBConfigRequest(t, url)
	require.Equal(t, fmt.Sprintf("resource not found for pid=%d", pid), string(respBody))
	require.Equal(t, http.StatusNotFound, statusCode)
}

func launchFakeProcess(ctx context.Context, t *testing.T, tmp, procname string) int {
	// creates a symlink to /usr/bin/sleep to be able to create a fake
	// postgres process.
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("could not find sleep util")
	}
	fakePgPath := filepath.Join(tmp, procname)
	if err := os.Symlink(sleepPath, fakePgPath); err != nil {
		t.Fatalf("could not create fake process symlink: %v", err)
	}

	cmd := exec.CommandContext(ctx, fakePgPath, "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start fake process %q: %v", procname, err)
	}

	return cmd.Process.Pid
}

func doDBConfigRequest(t *testing.T, url string) (int, http.Header, []byte) {
	rec := httptest.NewRecorder()

	m := &complianceModule{}
	m.handleScanDBConfig(rec, httptest.NewRequest(http.MethodGet, url, nil))

	response := rec.Result()

	defer response.Body.Close()
	resBytes, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, response.Header, resBytes
}
