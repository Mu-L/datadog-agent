// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package installer

import (
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"time"

	e2eos "github.com/DataDog/test-infra-definitions/components/os"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const (
	injectOCIPath = "/opt/datadog-packages/datadog-apm-inject"
	injectDebPath = "/opt/datadog/apm"
)

type packageApmInjectSuite struct {
	packageBaseSuite
}

func testApmInjectAgent(os e2eos.Descriptor, arch e2eos.Architecture, method InstallMethodOption) packageSuite {
	return &packageApmInjectSuite{
		packageBaseSuite: newPackageSuite("apm-inject", os, arch, method),
	}
}

func (s *packageApmInjectSuite) TestInstall() {
	s.host.InstallDocker()
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()
	s.host.WaitForUnitActive(s.T(), "datadog-agent.service", "datadog-agent-trace.service")

	s.host.StartExamplePythonApp()
	defer s.host.StopExamplePythonApp()
	s.host.StartExamplePythonAppInDocker()
	defer s.host.StopExamplePythonAppInDocker()

	s.host.AssertPackageInstalledByInstaller("datadog-apm-inject", "datadog-apm-library-python")
	s.host.AssertPackageNotInstalledByPackageManager("datadog-apm-inject", "datadog-apm-library-python")
	s.host.AssertPackageInstalledByPackageManager("datadog-agent")
	state := s.host.State()
	state.AssertFileExists("/opt/datadog-packages/run/environment", 0644, "root", "root")
	state.AssertSymlinkExists("/etc/default/datadog-agent", "/opt/datadog-packages/run/environment", "root", "root")
	state.AssertSymlinkExists("/etc/default/datadog-agent-trace", "/opt/datadog-packages/run/environment", "root", "root")
	state.AssertDirExists("/var/log/datadog/dotnet", 0777, "root", "root")
	state.AssertFileExists("/etc/ld.so.preload", 0644, "root", "root")
	state.AssertFileExists("/usr/bin/dd-host-install", 0755, "root", "root")
	state.AssertFileExists("/usr/bin/dd-container-install", 0755, "root", "root")
	state.AssertDirExists("/etc/datadog-agent/inject", 0755, "root", "root")
	if s.os == e2eos.Ubuntu2404 || s.os == e2eos.Debian12 {
		state.AssertDirExists("/etc/apparmor.d/abstractions/datadog.d", 0755, "root", "root")
		state.AssertFileExists("/etc/apparmor.d/abstractions/datadog.d/injector", 0644, "root", "root")
	}
	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
	s.assertStableConfig(map[string]interface{}{})

	traceID := rand.Uint64()
	s.host.CallExamplePythonApp(fmt.Sprint(traceID))
	traceIDDocker := rand.Uint64()
	s.host.CallExamplePythonAppInDocker(fmt.Sprint(traceIDDocker))

	s.assertTraceReceived(traceID)
	s.assertTraceReceived(traceIDDocker)
}

func (s *packageApmInjectSuite) TestUninstall() {
	s.host.InstallDocker()
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	s.Purge()

	s.assertLDPreloadNotInstrumented()
	s.assertDockerdNotInstrumented()

	state := s.host.State()
	state.AssertPathDoesNotExist("/usr/bin/dd-host-install")
	state.AssertPathDoesNotExist("/usr/bin/dd-container-install")
	state.AssertPathDoesNotExist("/etc/apparmor.d/abstractions/datadog.d/injector")
}

func (s *packageApmInjectSuite) TestDockerAdditionalFields() {
	s.host.InstallDocker()
	// Broken /etc/docker/daemon.json syntax
	s.host.SetBrokenDockerConfig()
	defer s.host.RemoveBrokenDockerConfig()
	_ = s.RunInstallScriptWithError("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.assertLDPreloadNotInstrumented()
	s.assertDockerdNotInstrumented()
}

func (s *packageApmInjectSuite) TestDockerBrokenJSON() {
	s.host.InstallDocker()
	// Additional fields in /etc/docker/daemon.json
	s.host.SetBrokenDockerConfigAdditionalFields()
	defer s.host.RemoveBrokenDockerConfig()
	_ = s.RunInstallScriptWithError("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.assertLDPreloadNotInstrumented()
	s.assertDockerdNotInstrumented()
}

func (s *packageApmInjectSuite) TestInstrumentDocker() {
	s.host.InstallDocker()
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=docker", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.assertLDPreloadNotInstrumented()
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestInstrumentHost() {
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=host", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertDockerdNotInstrumented()
}

func (s *packageApmInjectSuite) TestInstrumentProfilingEnabled() {
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=host", "DD_APM_INSTRUMENTATION_LIBRARIES=python", "DD_PROFILING_ENABLED=auto", "DD_DATA_STREAMS_ENABLED=true")
	defer s.Purge()
	s.assertStableConfig(map[string]interface{}{
		"DD_PROFILING_ENABLED":    "auto",
		"DD_DATA_STREAMS_ENABLED": true,
	})
}

func (s *packageApmInjectSuite) TestInstrumentDefault() {
	s.host.InstallDocker()
	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestSystemdReload() {
	s.host.InstallDocker()
	s.RunInstallScript()
	defer s.Purge()

	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	s.host.WaitForUnitActive(s.T(), "datadog-agent.service", "datadog-agent-trace.service")
	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
}

// TestUpgrade_InjectorDeb_To_InjectorOCI tests the upgrade from the DEB injector to the OCI injector.
// Library package is OCI.
func (s *packageApmInjectSuite) TestUpgrade_InjectorDeb_To_InjectorOCI() {
	if s.os.Flavor == e2eos.Suse {
		s.T().Skip("Can't install APM deb/rpm packages on Suse, they were never released")
	}

	s.host.InstallDocker()

	// Deb install using today's defaults
	s.RunInstallScript(
		"TESTING_APT_URL=",
		"TESTING_APT_REPO_VERSION=",
		"TESTING_YUM_URL=",
		"TESTING_YUM_VERSION_PATH=",
		"DD_REPO_URL=datadoghq.com",
	)
	s.host.Run("sudo apt-get install -y datadog-apm-inject datadog-apm-library-python || sudo yum install -y datadog-apm-inject datadog-apm-library-python")
	s.host.Run("sudo dd-container-install --no-agent-restart")
	s.host.Run("sudo dd-host-install --no-agent-restart")
	defer s.Purge()
	defer s.purgeInjectorDebInstall()

	s.assertLDPreloadInstrumented(injectDebPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectDebPath)

	// OCI install
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
	s.host.AssertPackageNotInstalledByPackageManager("datadog-apm-inject", "datadog-apm-library-python")

}

// TestUpgrade_InjectorOCI_To_InjectorDeb tests the upgrade from the OCI injector to the DEB injector.
// Library package is OCI.
func (s *packageApmInjectSuite) TestUpgrade_InjectorOCI_To_InjectorDeb() {
	if s.os.Flavor == e2eos.Suse {
		s.T().Skip("Can't install APM deb/rpm packages on Suse, they were never released")
	}

	s.host.InstallDocker()

	// OCI install
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)

	// Deb install using today's defaults
	s.RunInstallScript(
		"TESTING_APT_URL=",
		"TESTING_APT_REPO_VERSION=",
		"TESTING_YUM_URL=",
		"TESTING_YUM_VERSION_PATH=",
		"DD_REPO_URL=datadoghq.com",
	)
	s.host.Run("sudo apt-get install -y datadog-apm-inject datadog-apm-library-python || sudo yum install -y datadog-apm-inject datadog-apm-library-python")
	defer s.purgeInjectorDebInstall()

	// OCI mustn't be overridden
	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestVersionBump() {
	s.host.InstallDocker()
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python:2.8.5",
		envForceVersion("datadog-apm-inject", "0.39.0-1"),
	)
	defer s.Purge()
	s.host.WaitForUnitActive(s.T(), "datadog-agent.service", "datadog-agent-trace.service")

	state := s.host.State()
	state.AssertDirExists("/opt/datadog-packages/datadog-apm-library-python/2.8.5", 0755, "root", "root")
	state.AssertSymlinkExists("/opt/datadog-packages/datadog-apm-library-python/stable", "/opt/datadog-packages/datadog-apm-library-python/2.8.5", "root", "root")

	state.AssertDirExists("/opt/datadog-packages/datadog-apm-inject/0.39.0", 0755, "root", "root")
	state.AssertSymlinkExists("/opt/datadog-packages/datadog-apm-inject/stable", "/opt/datadog-packages/datadog-apm-inject/0.39.0", "root", "root")

	s.host.StartExamplePythonApp()
	defer s.host.StopExamplePythonApp()

	traceID := rand.Uint64()
	s.host.CallExamplePythonApp(fmt.Sprint(traceID))
	s.assertTraceReceived(traceID)

	// Re-run the install script with the latest tracer version
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python:2.9.2",
		envForceVersion("datadog-apm-inject", "0.40.0-1"),
	)
	s.host.WaitForUnitActive(s.T(), "datadog-agent.service", "datadog-agent-trace.service")

	// Today we expect the previous dir to be fully removed and the new one to be symlinked
	state = s.host.State()
	state.AssertPathDoesNotExist("/opt/datadog-packages/datadog-apm-library-python/2.8.5")
	state.AssertDirExists("/opt/datadog-packages/datadog-apm-library-python/2.9.2", 0755, "root", "root")
	state.AssertSymlinkExists("/opt/datadog-packages/datadog-apm-library-python/stable", "/opt/datadog-packages/datadog-apm-library-python/2.9.2", "root", "root")

	state.AssertPathDoesNotExist("/opt/datadog-packages/datadog-apm-inject/0.39.0")
	state.AssertDirExists("/opt/datadog-packages/datadog-apm-inject/0.40.0", 0755, "root", "root")
	state.AssertSymlinkExists("/opt/datadog-packages/datadog-apm-inject/stable", "/opt/datadog-packages/datadog-apm-inject/0.40.0", "root", "root")

	s.host.StartExamplePythonAppInDocker()
	defer s.host.StopExamplePythonAppInDocker()

	traceID = rand.Uint64()
	s.host.CallExamplePythonApp(fmt.Sprint(traceID))
	traceIDDocker := rand.Uint64()
	s.host.CallExamplePythonAppInDocker(fmt.Sprint(traceIDDocker))

	s.assertTraceReceived(traceID)
	s.assertTraceReceived(traceIDDocker)
}

func (s *packageApmInjectSuite) TestInstrument() {
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=host",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()
	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdNotInstrumented()

	s.host.InstallDocker()

	_, err := s.Env().RemoteHost.Execute("sudo datadog-installer apm instrument docker")
	assert.NoError(s.T(), err)

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestPackagePinning() {
	s.host.InstallDocker()

	// Deb install using today's defaults
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python:2.8.5,dotnet",
	)
	defer s.Purge()
	defer s.purgeInjectorDebInstall()

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)

	s.host.AssertPackageInstalledByInstaller("datadog-apm-library-python", "datadog-apm-library-dotnet")
	s.host.AssertPackageVersion("datadog-apm-library-python", "2.8.5")
}

func (s *packageApmInjectSuite) TestUninstrument() {
	s.host.InstallDocker()
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=all",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)

	_, err := s.Env().RemoteHost.Execute("sudo datadog-installer apm uninstrument")
	assert.NoError(s.T(), err)

	state := s.host.State()
	state.AssertDirExists("/opt/datadog-packages/datadog-apm-inject/stable", 0755, "root", "root")
	s.assertLDPreloadNotInstrumented()
	s.assertDockerdNotInstrumented()
	if s.os == e2eos.Ubuntu2404 || s.os == e2eos.Debian12 {
		s.assertAppArmorProfile() // AppArmor profile should still be there
	}
}

func (s *packageApmInjectSuite) TestInstrumentScripts() {
	if s.os.Flavor == e2eos.Suse {
		s.T().Skip("Can't install APM deb/rpm packages on Suse, they were never released")
	}

	s.host.InstallDocker()

	// Deb install using today's defaults
	s.RunInstallScript(
		"TESTING_APT_URL=",
		"TESTING_APT_REPO_VERSION=",
		"TESTING_YUM_URL=",
		"TESTING_YUM_VERSION_PATH=",
		"DD_REPO_URL=datadoghq.com",
	)
	s.host.Run("sudo apt-get install -y datadog-apm-inject datadog-apm-library-python || sudo yum install -y datadog-apm-inject datadog-apm-library-python")
	defer s.purgeInjectorDebInstall()

	state := s.host.State()
	state.AssertFileExists("/usr/bin/dd-host-install", 0755, "root", "root")
	state.AssertFileExists("/usr/bin/dd-container-install", 0755, "root", "root")
	state.AssertFileExists("/usr/bin/dd-cleanup", 0755, "root", "root")

	// OCI install
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=host",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()

	// Old commands still work
	s.Env().RemoteHost.MustExecute("dd-host-install --uninstall")
	s.assertLDPreloadNotInstrumented()
	s.Env().RemoteHost.MustExecute("dd-container-install --uninstall")
	s.assertDockerdNotInstrumented()

	// Remove the deb injector, we should still be instrumented
	s.Env().RemoteHost.MustExecute("sudo datadog-installer apm instrument")
	s.Env().RemoteHost.MustExecute("sudo apt-get remove -y --purge datadog-apm-inject || sudo yum remove -y datadog-apm-inject")
	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestInstrumentDockerInactive() {
	s.host.InstallDocker()
	s.Env().RemoteHost.MustExecute("sudo systemctl stop docker")

	s.RunInstallScript("DD_APM_INSTRUMENTATION_ENABLED=all", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()

	s.host.InstallDocker() // Restart docker cleanly

	s.assertLDPreloadInstrumented(injectOCIPath)
	s.assertSocketPath()
	s.assertDockerdInstrumented(injectOCIPath)
}

func (s *packageApmInjectSuite) TestInstallStandaloneLib() {
	s.RunInstallScript("DD_INSTALLER=true", "DD_APM_INSTRUMENTATION_LIBRARIES=python")
	defer s.Purge()
	s.host.AssertPackageNotInstalledByPackageManager("datadog-apm-library-python")
	s.host.AssertPackageInstalledByInstaller("datadog-apm-library-python")
}

func (s *packageApmInjectSuite) TestDefaultPackageVersion() {
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=host",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()
	s.host.AssertPackagePrefix("datadog-apm-library-python", "3")
}

func (s *packageApmInjectSuite) TestInstallWithUmask() {
	oldmask := s.host.SetUmask("0027")
	defer s.host.SetUmask(oldmask)
	s.TestInstall()
}

func (s *packageApmInjectSuite) TestAppArmor() {
	if s.os != e2eos.Ubuntu2404 && s.os != e2eos.Debian12 {
		s.T().Skip("AppArmor not installed by default")
	}
	assert.Contains(s.T(), s.Env().RemoteHost.MustExecute("sudo aa-enabled"), "Yes")
	s.RunInstallScript(
		"DD_APM_INSTRUMENTATION_ENABLED=host",
		"DD_APM_INSTRUMENTATION_LIBRARIES=python",
	)
	defer s.Purge()
	s.assertAppArmorProfile()
	assert.Contains(s.T(), s.Env().RemoteHost.MustExecute("sudo aa-enabled"), "Yes")
	s.Env().RemoteHost.MustExecute("sudo apt update && sudo apt install -y isc-dhcp-client")
	res := s.Env().RemoteHost.MustExecute("sudo DD_APM_INSTRUMENTATION_DEBUG=true /usr/sbin/dhclient 2>&1")
	assert.Contains(s.T(), res, "not injecting; on deny list")
}

func (s *packageApmInjectSuite) assertTraceReceived(traceID uint64) {
	found := assert.Eventually(s.T(), func() bool {
		tracePayloads, err := s.Env().FakeIntake.Client().GetTraces()
		assert.NoError(s.T(), err)
		for _, tracePayload := range tracePayloads {
			for _, tracerPayload := range tracePayload.TracerPayloads {
				for _, chunk := range tracerPayload.Chunks {
					for _, span := range chunk.Spans {
						if span.TraceID == traceID {
							return true
						}
					}
				}
			}
		}
		return false
	}, time.Second*30, time.Second*1)
	if !found {
		tracePayloads, _ := s.Env().FakeIntake.Client().GetTraces()
		s.T().Logf("Traces received: %v", tracePayloads)
		s.T().Logf("Server logs: %v", s.Env().RemoteHost.MustExecute("cat /tmp/server.log"))
		s.T().Logf("Trace Agent logs: %v", s.Env().RemoteHost.MustExecute("cat /var/log/datadog/trace-agent.log"))
	}
}

func (s *packageApmInjectSuite) assertLDPreloadInstrumented(libPath string) {
	content, err := s.host.ReadFile("/etc/ld.so.preload")
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), string(content), libPath)
}

func (s *packageApmInjectSuite) assertStableConfig(expectedConfigs map[string]interface{}) {
	if len(expectedConfigs) == 0 {
		return
	}

	state := s.host.State()
	state.AssertFileExists("/etc/datadog-agent/application_monitoring.yaml", 0644, "dd-agent", "dd-agent")
	content, err := s.host.ReadFile("/etc/datadog-agent/application_monitoring.yaml")
	assert.NoError(s.T(), err)

	actualStableConfig := map[string]interface{}{}
	err = yaml.Unmarshal(content, &actualStableConfig)
	assert.NoError(s.T(), err)

	assert.Contains(s.T(), actualStableConfig, "apm_configuration_default")
	assert.Equal(s.T(), expectedConfigs, actualStableConfig["apm_configuration_default"])
}

func (s *packageApmInjectSuite) assertSocketPath() {
	output := s.host.Run("sh -c 'python3 -c \"import os; print(os.environ)\"'")
	assert.Contains(s.T(), output, "'DD_INJECTION_ENABLED': 'tracer'") // this is an env var set by the injector
}

func (s *packageApmInjectSuite) assertLDPreloadNotInstrumented() {
	exists, err := s.host.FileExists("/etc/ld.so.preload")
	assert.NoError(s.T(), err)
	if exists {
		content, err := s.host.ReadFile("/etc/ld.so.preload")
		assert.NoError(s.T(), err)
		assert.NotContains(s.T(), string(content), injectOCIPath)
		assert.NotContains(s.T(), string(content), injectDebPath)
	}
	output := s.host.Run("sh -c 'python3 -c \"import os; print(os.environ)\"'")
	assert.NotContains(s.T(), output, "'DD_INJECTION_ENABLED': 'tracer'")
}

func (s *packageApmInjectSuite) assertDockerdInstrumented(path string) {
	content, err := s.host.ReadFile("/etc/docker/daemon.json")
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), string(content), path)
	runtimeConfig := s.host.GetDockerRuntimePath("dd-shim")
	if path == injectOCIPath {
		assert.Equal(s.T(), runtimeConfig, filepath.Join(path, "stable", "inject", "auto_inject_runc"))
	} else {
		assert.Equal(s.T(), runtimeConfig, filepath.Join(path, "inject", "auto_inject_runc"))
	}
}

func (s *packageApmInjectSuite) assertDockerdNotInstrumented() {
	exists, err := s.host.FileExists("/etc/docker/daemon.json")
	assert.NoError(s.T(), err)
	if exists {
		content, err := s.host.ReadFile("/etc/docker/daemon.json")
		assert.NoError(s.T(), err)
		assert.NotContains(s.T(), string(content), injectOCIPath)
		assert.NotContains(s.T(), string(content), injectDebPath)
	}
	runtimeConfig := s.host.GetDockerRuntimePath("dd-shim")
	assert.Equal(s.T(), runtimeConfig, "")
}

func (s *packageApmInjectSuite) assertAppArmorProfile() {
	content, err := s.host.ReadFile("/etc/apparmor.d/abstractions/datadog.d/injector")
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), string(content), `/opt/datadog-packages/** rix,
/proc/@{pid}/** rix,
/run/datadog/apm.socket rw,`)
	assert.Contains(s.T(), s.Env().RemoteHost.MustExecute("sudo aa-enabled"), "Yes")
}

func (s *packageApmInjectSuite) purgeInjectorDebInstall() {
	s.Env().RemoteHost.MustExecute("sudo rm -f /opt/datadog-packages/run/environment")
	s.Env().RemoteHost.MustExecute("sudo rm -f /etc/datadog-agent/datadog.yaml")

	packageList := []string{
		"datadog-agent",
		"datadog-apm-inject",
		"datadog-apm-library-python",
	}
	s.Env().RemoteHost.Execute(fmt.Sprintf("sudo apt-get remove -y --purge %[1]s || sudo yum remove -y %[1]s", strings.Join(packageList, " ")))
}
