// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package common contains basic test operation for agent-platform tests
package common

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	componentos "github.com/DataDog/test-infra-definitions/components/os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentclient "github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client/agentclient"
	boundport "github.com/DataDog/datadog-agent/test/new-e2e/tests/agent-platform/common/bound-port"
)

// CheckAgentBehaviour runs test to check the agent is behaving as expected
func CheckAgentBehaviour(t *testing.T, client *TestClient) {
	t.Run("datadog-agent service running", func(tt *testing.T) {
		_, err := client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent service should be running")
	})

	t.Run("datadog-agent checks running", func(tt *testing.T) {
		var statusOutputJSON map[string]any
		var err error
		result := false
		for try := 0; try < 15 && !result; try++ {
			err = json.Unmarshal([]byte(client.AgentClient.Status(agentclient.WithArgs([]string{"-j"})).Content), &statusOutputJSON)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}

			if runnerStats, ok := statusOutputJSON["runnerStats"]; ok {
				runnerStatsMap := runnerStats.(map[string]any)
				if checks, ok := runnerStatsMap["Checks"]; ok {
					checksMap := checks.(map[string]any)
					result = len(checksMap) > 0
				}
			}

			if !result {
				time.Sleep(1 * time.Second)
			}
		}

		if !result {
			require.NoError(tt, err)
		}

		require.True(tt, result, "status output should contain running checks")
	})

	t.Run("status command infos", func(tt *testing.T) {
		statusOutput := client.AgentClient.Status().Content
		require.Contains(tt, statusOutput, "Forwarder")
		require.Contains(tt, statusOutput, "Host Info")
		require.Contains(tt, statusOutput, "DogStatsD")
	})

	t.Run("status command no errors", func(tt *testing.T) {
		statusOutput := client.AgentClient.Status().Content

		// API Key is invalid we should not check for the following error
		statusOutput = strings.ReplaceAll(statusOutput, "[ERROR] API Key is invalid", "API Key is invalid")

		// Ignore errors specifically due to NTP flakiness.
		if strings.Contains(statusOutput, "Error: failed to get clock offset from any ntp host") {
			// The triggering error will look something like this:
			//   Instance ID: ntp:4c427a42a70bbf8 [ERROR]
			re := regexp.MustCompile(`Instance\sID[:]\sntp[:][a-z0-9]+\s\[ERROR\]`)
			statusOutput = re.ReplaceAllString(statusOutput, "Instance ID: ntp [ignored]")
		}

		require.NotContains(tt, statusOutput, "ERROR")
	})
}

// CheckDogstatdAgentBehaviour runs tests to check the agent behave properly with dogstatsd
func CheckDogstatdAgentBehaviour(t *testing.T, client *TestClient) {
	t.Run("dogstatsd service running", func(tt *testing.T) {
		_, err := client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "dogstatsd service should be running")
	})

	t.Run("dogstatsd config file exists", func(tt *testing.T) {
		_, err := client.FileManager.FileExists(fmt.Sprintf("%s/%s", client.Helper.GetConfigFolder(), "dogstatsd.yaml"))
		require.NoError(tt, err, "dogstatsd config file should be present")
	})
}

// CheckAgentStops runs tests to check the agent can stop properly
func CheckAgentStops(t *testing.T, client *TestClient) {
	t.Run("stops", func(tt *testing.T) {
		_, err := client.SvcManager.Stop(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.Error(tt, err, "datadog-agent service should be stopped")
	})

	t.Run("refuse connections", func(tt *testing.T) {
		_, err := client.AgentClient.StatusWithError()
		require.Error(tt, err, "status should error")
	})

	t.Run("no running processes", func(tt *testing.T) {
		running, err := RunningAgentProcesses(client)
		require.NoError(tt, err)
		require.Empty(tt, running, "no agent process should be running")
	})

	t.Run("starts after stop", func(tt *testing.T) {
		_, err := client.SvcManager.Start(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent should be running")
	})
}

// CheckDogstatsdAgentStops runs tests to check the agent can stop properly
func CheckDogstatsdAgentStops(t *testing.T, client *TestClient) {
	t.Run("stops", func(tt *testing.T) {
		_, err := client.SvcManager.Stop(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.Error(tt, err, "datadog-dogstatsd service should be stopped")
	})

	t.Run("no running processes", func(tt *testing.T) {
		running, err := RunningAgentProcesses(client)
		require.NoError(tt, err)
		require.Empty(tt, running, "no agent process should be running")
	})

	t.Run("starts after stop", func(tt *testing.T) {
		_, err := client.SvcManager.Start(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-dogstatsd should be running")
	})
}

// CheckAgentRestarts runs tests to check the agent can restart properly
func CheckAgentRestarts(t *testing.T, client *TestClient) {
	t.Run("start when stopped", func(tt *testing.T) {
		// If the agent is not stopped yet, stop it
		if _, err := client.SvcManager.Status(client.Helper.GetServiceName()); err == nil {
			_, err := client.SvcManager.Stop(client.Helper.GetServiceName())
			require.NoError(tt, err)
		}

		_, err := client.SvcManager.Start(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent should restart when stopped")
	})

	t.Run("restart when running", func(tt *testing.T) {
		// If the agent is not started yet, start it
		if _, err := client.SvcManager.Status(client.Helper.GetServiceName()); err != nil {
			_, err := client.SvcManager.Start(client.Helper.GetServiceName())
			require.NoError(tt, err)
		}

		_, err := client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent should restart when running")
	})
}

// CheckDogstatsdAgentRestarts runs tests to check the agent can restart properly
func CheckDogstatsdAgentRestarts(t *testing.T, client *TestClient) {
	t.Run("restart when stopped", func(tt *testing.T) {
		// If the agent is not stopped yet, stop it
		if _, err := client.SvcManager.Status(client.Helper.GetServiceName()); err == nil {
			_, err := client.SvcManager.Stop(client.Helper.GetServiceName())
			require.NoError(tt, err)
		}

		_, err := client.SvcManager.Start(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-dogstatsd should restart when stopped")
	})

	t.Run("restart when running", func(tt *testing.T) {
		// If the agent is not started yet, start it
		if _, err := client.SvcManager.Status(client.Helper.GetServiceName()); err != nil {
			_, err := client.SvcManager.Start(client.Helper.GetServiceName())
			require.NoError(tt, err)
		}

		_, err := client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err)

		_, err = client.SvcManager.Status(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-dogstatsd should restart when running")
	})
}

const (
	// ExpectedPythonVersion2 is the expected python 2 version
	// Bump this version when the version in omnibus/config/software/python2.rb changes
	ExpectedPythonVersion2 = "2.7.18"
	// ExpectedPythonVersion3 is the expected python 3 version
	// Bump this version when the version in omnibus/config/software/python3.rb changes
	ExpectedPythonVersion3 = "3.12.11"
)

// SetAgentPythonMajorVersion set the python major version in the agent config and restarts the agent
func SetAgentPythonMajorVersion(t *testing.T, client *TestClient, majorVersion string) {
	t.Run(fmt.Sprintf("set python version %s and restarts", majorVersion), func(tt *testing.T) {
		configFilePath := client.Helper.GetConfigFolder() + client.Helper.GetConfigFileName()
		err := client.SetConfig(configFilePath, "python_version", majorVersion)
		require.NoError(tt, err, "failed to set python version: ", err)

		_, err = client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err, "agent should be able to restart after editing python version")
	})
}

// CheckAgentPython runs tests to check the agent use the correct python version
func CheckAgentPython(t *testing.T, client *TestClient, expectedVersion string) {
	t.Run(fmt.Sprintf("check python %s is used", expectedVersion), func(tt *testing.T) {
		require.EventuallyWithT(tt, func(c *assert.CollectT) {
			statusVersion, err := client.GetPythonVersion()
			require.NoError(c, err)
			actualPythonVersion := statusVersion
			require.Equal(c, expectedVersion, actualPythonVersion)
		}, 2*time.Minute, 5*time.Second)
	})
}

// CheckApmEnabled runs tests to check the agent behave properly with APM enabled
func CheckApmEnabled(t *testing.T, client *TestClient) {
	t.Run("port bound apm enabled", func(tt *testing.T) {
		configFilePath := client.Helper.GetConfigFolder() + client.Helper.GetConfigFileName()

		err := client.SetConfig(configFilePath, "apm_config.enabled", "true")
		require.NoError(tt, err)

		_, err = client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err)

		var boundPort boundport.BoundPort
		if !assert.EventuallyWithT(tt, func(c *assert.CollectT) {
			boundPort, _ = AssertPortBoundByService(c, client, 8126, "trace-agent")
		}, 1*time.Minute, 500*time.Millisecond) {
			err := fmt.Errorf("port 8126 should be bound when APM is enabled")
			if err != nil && client.Host.OSFamily == componentos.LinuxFamily {
				err = fmt.Errorf("%w\n%s", err, ReadJournalCtl(t, client, "trace-agent\\|datadog-agent-trace"))
			}
			t.Fatalf("%s", err.Error())
		}

		require.EqualValues(t, "127.0.0.1", boundPort.LocalAddress(), "trace-agent should only be listening locally")
	})
}

// CheckApmDisabled runs tests to check the agent behave properly when APM is disabled
func CheckApmDisabled(t *testing.T, client *TestClient) {
	t.Run("trace-agent not running when disabled", func(tt *testing.T) {
		configFilePath := client.Helper.GetConfigFolder() + client.Helper.GetConfigFileName()

		err := client.SetConfig(configFilePath, "apm_config.enabled", "false")
		require.NoError(tt, err)

		_, err = client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err)

		// On Linux, trace-agent will be started by the service manager and then exit
		// after a bit if it is not enabled.
		// On Windows, datadog-agent won't start trace-agent if it is not enabled, however
		// PowerShell Restart-Service may restart trace-agent if it was already running, and
		// trace-agent will run for a bit before exiting.
		require.Eventually(tt, func() bool {
			return !AgentProcessIsRunning(client, "trace-agent")
		}, 1*time.Minute, 500*time.Millisecond, "trace-agent should not be running ", err)
	})
}

// CheckCWSBehaviour runs tests to check the agent behave correctly when CWS is enabled
func CheckCWSBehaviour(t *testing.T, client *TestClient) {
	t.Run("enable CWS and restarts", func(tt *testing.T) {
		err := client.SetConfig(client.Helper.GetConfigFolder()+"system-probe.yaml", "runtime_security_config.enabled", "true")
		require.NoError(tt, err)
		err = client.SetConfig(client.Helper.GetConfigFolder()+"security-agent.yaml", "runtime_security_config.enabled", "true")
		require.NoError(tt, err)

		_, err = client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent should restart after CWS is enabled")
	})

	t.Run("security-agent is running", func(tt *testing.T) {
		var err error
		require.Eventually(tt, func() bool {
			return AgentProcessIsRunning(client, "security-agent")
		}, 1*time.Minute, 500*time.Millisecond, "security-agent should be running ", err)
	})

	t.Run("system-probe is running", func(tt *testing.T) {
		var err error
		require.Eventually(tt, func() bool {
			return AgentProcessIsRunning(client, "system-probe")
		}, 1*time.Minute, 500*time.Millisecond, "system-probe should be running ", err)
	})
}

// CheckSystemProbeBehavior runs tests to check the agent behave correctly when system-probe is enabled
func CheckSystemProbeBehavior(t *testing.T, client *TestClient) {
	t.Run("enable system-probe and restarts", func(tt *testing.T) {
		err := client.SetConfig(client.Helper.GetConfigFolder()+"system-probe.yaml", "system_probe_config.enabled", "true")
		require.NoError(tt, err)

		err = client.SetConfig(client.Helper.GetConfigFolder()+"system-probe.yaml", "system_probe_config.enabled", "true")
		require.NoError(tt, err)

		_, err = client.SvcManager.Restart(client.Helper.GetServiceName())
		require.NoError(tt, err, "datadog-agent should restart after CWS is enabled")
	})

	t.Run("system-probe is running", func(tt *testing.T) {
		var err error
		require.Eventually(tt, func() bool {
			return AgentProcessIsRunning(client, "system-probe")
		}, 1*time.Minute, 500*time.Millisecond, "system-probe should be running ", err)
	})

	t.Run("ebpf programs are unpacked and valid", func(tt *testing.T) {
		ebpfPath := "/opt/datadog-agent/embedded/share/system-probe/ebpf"
		output, err := client.Host.Execute(fmt.Sprintf("find %s -name '*.o'", ebpfPath))
		require.NoError(tt, err)
		files := strings.Split(strings.TrimSpace(output), "\n")
		require.Greater(tt, len(files), 0, "ebpf object files should be present")

		_, err = client.Host.Execute("command -v readelf")
		if err != nil {
			tt.Skip("readelf is not available on the host")
			return
		}

		hostArch, err := client.Host.Execute("uname -m")
		require.NoError(tt, err)
		hostArch = strings.TrimSpace(hostArch)
		if hostArch == "aarch64" {
			hostArch = "arm64"
		}
		archMetadata := fmt.Sprintf("<arch:%s>", hostArch)

		for _, file := range files {
			file = strings.TrimSpace(file)
			ddMetadata, err := client.Host.Execute(fmt.Sprintf("readelf -p dd_metadata %s", file))
			require.NoError(tt, err, "readelf should not error, file is %s", file)
			require.Contains(tt, ddMetadata, archMetadata, "invalid arch metadata")
		}
	})
}
