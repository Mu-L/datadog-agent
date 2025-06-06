// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package flare

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"gopkg.in/yaml.v2"

	procmodel "github.com/DataDog/agent-payload/v5/process"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	flarehelpers "github.com/DataDog/datadog-agent/comp/core/flare/helpers"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipcmock "github.com/DataDog/datadog-agent/comp/core/ipc/mock"
	"github.com/DataDog/datadog-agent/comp/core/secrets/secretsimpl"
	"github.com/DataDog/datadog-agent/comp/core/settings/settingsimpl"
	"github.com/DataDog/datadog-agent/comp/core/status"
	"github.com/DataDog/datadog-agent/comp/core/status/statusimpl"
	taggerfx "github.com/DataDog/datadog-agent/comp/core/tagger/fx"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafx "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx"
	processapiserver "github.com/DataDog/datadog-agent/comp/process/apiserver"
	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	model "github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestGoRoutines(t *testing.T) {
	expected := "No Goroutines for you, my friend!"
	ipcComp := ipcmock.New(t)

	ts := ipcComp.NewMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s", expected)
	}))

	remoteProvider := RemoteFlareProvider{
		IPC: ipcComp,
	}

	content, err := remoteProvider.getHTTPCallContent(ts.URL)
	require.NoError(t, err)
	assert.Equal(t, expected, string(content))
}

func createTestFile(t *testing.T, filename string) string {
	path := filepath.Join(t.TempDir(), filename)
	require.NoError(t, os.WriteFile(path, []byte("mockfilecontent"), os.ModePerm))
	return path
}

func TestRegistryJSON(t *testing.T) {
	srcDir := createTestFile(t, "registry.json")

	confMock := configmock.New(t)
	confMock.SetWithoutSource("logs_config.run_path", filepath.Dir(srcDir))

	mock := flarehelpers.NewFlareBuilderMock(t, false)
	getRegistryJSON(mock)

	mock.AssertFileContent("mockfilecontent", "registry.json")
}

func setupIPCAddress(t *testing.T, confMock model.Config, URL string) {
	u, err := url.Parse(URL)
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)

	confMock.SetWithoutSource("cmd_host", host)
	confMock.SetWithoutSource("cmd_port", port)
	confMock.SetWithoutSource("process_config.cmd_port", port)
}

func setupProcessAPIServer(t *testing.T, port int) {
	_ = fxutil.Test[processapiserver.Component](t, fx.Options(
		processapiserver.Module(),
		core.MockBundle(),
		fx.Replace(config.MockParams{Overrides: map[string]interface{}{
			"process_config.cmd_port": port,
		}}),
		workloadmetafx.Module(workloadmeta.NewParams()),
		fx.Supply(
			status.Params{
				PythonVersionGetFunc: func() string { return "n/a" },
			},
		),
		taggerfx.Module(),
		statusimpl.Module(),
		settingsimpl.MockModule(),
		secretsimpl.MockModule(),
		fx.Provide(func() ipc.Component { return ipcmock.New(t) }),
	))
}

func TestGetAgentTaggerList(t *testing.T) {
	tagMap := make(map[string]types.TaggerListEntity)
	tagMap["random_prefix://random_id"] = types.TaggerListEntity{
		Tags: map[string][]string{
			"docker_source_name": {"docker_image:custom-agent:latest", "image_name:custom-agent"},
		},
	}
	resp := types.TaggerListResponse{
		Entities: tagMap,
	}
	ipcComp := ipcmock.New(t)

	ts := ipcComp.NewMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		out, _ := json.Marshal(resp)
		w.Write(out)
	}))

	setupIPCAddress(t, configmock.New(t), ts.URL)

	remoteProvider := RemoteFlareProvider{
		IPC: ipcComp,
	}

	content, err := remoteProvider.getAgentTaggerList()
	require.NoError(t, err)

	assert.Contains(t, string(content), "random_prefix://random_id")
	assert.Contains(t, string(content), "docker_source_name")
	assert.Contains(t, string(content), "docker_image:custom-agent:latest")
	assert.Contains(t, string(content), "image_name:custom-agent")
}

func TestGetWorkloadList(t *testing.T) {
	workloadMap := make(map[string]workloadmeta.WorkloadEntity)
	workloadMap["kind_id"] = workloadmeta.WorkloadEntity{
		Infos: map[string]string{
			"container_id_1": "Name: init-volume ID: e19e1ba787",
			"container_id_2": "Name: init-config ID: 4e0ffee5d6",
		},
	}
	resp := workloadmeta.WorkloadDumpResponse{
		Entities: workloadMap,
	}
	ipcComp := ipcmock.New(t)

	ts := ipcComp.NewMockServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		out, _ := json.Marshal(resp)
		w.Write(out)
	}))

	setupIPCAddress(t, configmock.New(t), ts.URL)

	remoteProvider := RemoteFlareProvider{
		IPC: ipcComp,
	}

	content, err := remoteProvider.getAgentWorkloadList()
	require.NoError(t, err)

	assert.Contains(t, string(content), "kind_id")
	assert.Contains(t, string(content), "container_id_1")
	assert.Contains(t, string(content), "Name: init-volume ID: e19e1ba787")
	assert.Contains(t, string(content), "container_id_2")
	assert.Contains(t, string(content), "Name: init-config ID: 4e0ffee5d6")
}

func TestVersionHistory(t *testing.T) {
	srcDir := createTestFile(t, "version-history.json")

	confMock := configmock.New(t)
	confMock.SetWithoutSource("run_path", filepath.Dir(srcDir))

	mock := flarehelpers.NewFlareBuilderMock(t, false)
	getVersionHistory(mock)

	mock.AssertFileContent("mockfilecontent", "version-history.json")
}

func TestProcessAgentFullConfig(t *testing.T) {
	type ProcessConfig struct {
		Enabled string `yaml:"enabled"`
	}

	globalCfg := struct {
		Apikey     string        `yaml:"api_key"`
		DDurl      string        `yaml:"dd_url"`
		ProcessCfg ProcessConfig `yaml:"process_config"`
	}{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"https://my-url.com",
		ProcessConfig{
			"true",
		},
	}

	exp := `api_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
dd_url: https://my-url.com
process_config:
  enabled: "true"
`
	// Setting an unused port to avoid problem when test run next to running Process Agent
	port := 56789
	cfg := configmock.New(t)
	cfg.SetWithoutSource("process_config.cmd_port", port)

	ipcComp := ipcmock.New(t)
	remoteProvider := RemoteFlareProvider{
		IPC: ipcComp,
	}

	t.Run("without process-agent running", func(t *testing.T) {
		content, err := remoteProvider.getProcessAgentFullConfig()
		require.NoError(t, err)
		assert.Equal(t, "error: process-agent is not running or is unreachable\n", string(content))
	})

	t.Run("with process-agent running", func(t *testing.T) {
		// Create a server to mock process-agent /config/all endpoint
		handler := func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			b, err := yaml.Marshal(globalCfg)
			require.NoError(t, err)

			_, err = w.Write(b)
			require.NoError(t, err)
		}
		srv := ipcComp.NewMockServer(http.HandlerFunc(handler))

		setupIPCAddress(t, cfg, srv.URL)

		content, err := remoteProvider.getProcessAgentFullConfig()
		require.NoError(t, err)
		assert.Equal(t, exp, string(content))
	})

	t.Run("verify auth", func(t *testing.T) {
		listener, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		setupProcessAPIServer(t, port)

		cfg := configmock.New(t)
		cfg.SetWithoutSource("process_config.process_discovery.enabled", true)
		cfg.SetWithoutSource("process_config.cmd_port", port)

		content, err := remoteProvider.getProcessAgentFullConfig()
		require.NoError(t, err)
		// if auth is not set, "no session token provided" would appear instead
		assert.Equal(t, "", string(content))
	})
}

func TestProcessAgentChecks(t *testing.T) {
	expectedProcesses := []procmodel.MessageBody{
		&procmodel.CollectorProc{
			Processes: []*procmodel.Process{
				{
					Pid: 1337,
				},
			},
		},
	}
	expectedProcessesJSON, err := json.Marshal(&expectedProcesses)
	require.NoError(t, err)

	expectedContainers := []procmodel.MessageBody{
		&procmodel.CollectorContainer{
			Containers: []*procmodel.Container{
				{
					Id: "yeet",
				},
			},
		},
	}
	expectedContainersJSON, err := json.Marshal(&expectedContainers)
	require.NoError(t, err)

	expectedProcessDiscoveries := []procmodel.MessageBody{
		&procmodel.CollectorProcDiscovery{
			ProcessDiscoveries: []*procmodel.ProcessDiscovery{
				{
					Pid: 9001,
				},
			},
		},
	}
	expectedProcessDiscoveryJSON, err := json.Marshal(&expectedProcessDiscoveries)
	require.NoError(t, err)

	ipcComp := ipcmock.New(t)

	t.Run("without process-agent running", func(t *testing.T) {
		mock := flarehelpers.NewFlareBuilderMock(t, false)

		remoteProvider := RemoteFlareProvider{
			IPC: ipcComp,
		}

		// Use a hostname that will fail to resolve even with AppGate enabled,
		// otherwise this test will timeout
		remoteProvider.getChecksFromProcessAgent(mock, func() (string, error) { return "[invalid][host]:1337", nil })
		mock.AssertFileContentMatch("error collecting data for 'process_discovery_check_output.json': .*", "process_discovery_check_output.json")
	})
	t.Run("with process-agent running", func(t *testing.T) {
		cfg := configmock.New(t)
		cfg.SetWithoutSource("process_config.process_collection.enabled", true)
		cfg.SetWithoutSource("process_config.container_collection.enabled", true)
		cfg.SetWithoutSource("process_config.process_discovery.enabled", true)

		handler := func(w http.ResponseWriter, r *http.Request) {
			var err error
			switch r.URL.Path {
			case "/check/process":
				_, err = w.Write(expectedProcessesJSON)
			case "/check/container":
				_, err = w.Write(expectedContainersJSON)
			case "/check/process_discovery":
				_, err = w.Write(expectedProcessDiscoveryJSON)
			default:
				t.Error("Unexpected url endpoint", r.URL.Path)
			}
			require.NoError(t, err)
		}

		at := ipcmock.New(t)

		srv := at.NewMockServer(http.HandlerFunc(handler))
		setupIPCAddress(t, configmock.New(t), srv.URL)

		mock := flarehelpers.NewFlareBuilderMock(t, false)
		remoteProvider := RemoteFlareProvider{
			IPC: ipcComp,
		}

		remoteProvider.getChecksFromProcessAgent(mock, getProcessAPIAddressPort)

		mock.AssertFileContent(string(expectedProcessesJSON), "process_check_output.json")
		mock.AssertFileContent(string(expectedContainersJSON), "container_check_output.json")
		mock.AssertFileContent(string(expectedProcessDiscoveryJSON), "process_discovery_check_output.json")
	})
	t.Run("verify auth", func(t *testing.T) {
		listener, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		setupProcessAPIServer(t, port)

		cfg := configmock.New(t)
		cfg.SetWithoutSource("process_config.process_discovery.enabled", true)
		cfg.SetWithoutSource("process_config.cmd_port", port)

		mock := flarehelpers.NewFlareBuilderMock(t, false)
		remoteProvider := RemoteFlareProvider{
			IPC: ipcComp,
		}

		remoteProvider.getChecksFromProcessAgent(mock, getProcessAPIAddressPort)

		// if auth is not set, "no session token provided" would appear instead
		mock.AssertFileContent("error collecting data for 'process_discovery_check_output.json': status code: 404, body: process_discovery check is not running or has not been scheduled yet", "process_discovery_check_output.json")
	})
}
