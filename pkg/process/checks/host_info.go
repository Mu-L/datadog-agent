// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	model "github.com/DataDog/agent-payload/v5/process"
	"google.golang.org/grpc"

	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameinterface"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/core"
	"github.com/DataDog/datadog-agent/pkg/util/fargate"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	ddgrpc "github.com/DataDog/datadog-agent/pkg/util/grpc"
	"github.com/DataDog/datadog-agent/pkg/util/hostname/validate"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// function for getting the fargate hostname
var getFargateHost = fargate.GetFargateHost

// HostInfo describes details of host information shared between various checks
type HostInfo struct {
	SystemInfo *model.SystemInfo
	HostName   string
	// host type of the agent, used to populate container payload with additional host information
	ContainerHostType model.ContainerHostType
}

// CollectHostInfo collects host information
func CollectHostInfo(config pkgconfigmodel.Reader, hostnameComp hostnameinterface.Component, ipc ipc.Component) (*HostInfo, error) {
	sysInfo, err := CollectSystemInfo()
	if err != nil {
		return nil, err
	}

	hostName, err := resolveHostName(config, hostnameComp, ipc)
	if err != nil {
		return nil, err
	}

	return &HostInfo{
		SystemInfo:        sysInfo,
		HostName:          hostName,
		ContainerHostType: getContainerHostType(),
	}, nil
}

func resolveHostName(config pkgconfigmodel.Reader, hostnameComp hostnameinterface.Component, ipc ipc.Component) (string, error) {
	// use the common agent hostname utility when not running in the process-agent or when running in Fargate
	if flavor.GetFlavor() != flavor.ProcessAgent && !fargate.IsFargateInstance() {
		hostName, err := hostnameComp.Get(context.TODO())
		if err != nil {
			return "", fmt.Errorf("error while getting hostname: %v", err)
		}
		return hostName, nil
	}

	var hostName string
	if config.IsSet("hostname") {
		hostName = config.GetString("hostname")
	}

	if err := validate.ValidHostname(hostName); err != nil {
		// lookup hostname if there is no config override or if the override is invalid
		agentBin := config.GetString("process_config.dd_agent_bin")
		connectionTimeout := config.GetDuration("process_config.grpc_connection_timeout_secs") * time.Second

		hostName, err = getHostname(context.Background(), agentBin, connectionTimeout, ipc)
		if err != nil {
			return "", log.Errorf("cannot get hostname: %v", err)
		}
	}
	return hostName, nil
}

// getHostname attempts to resolve the hostname in the following order: the main datadog agent via grpc, the main agent
// via cli and lastly falling back to os.Hostname() if it is unavailable
func getHostname(ctx context.Context, ddAgentBin string, grpcConnectionTimeout time.Duration, ipc ipc.Component) (string, error) {
	// Fargate is handled as an exceptional case (there is no concept of a host, so we use the ARN in-place).
	if fargate.IsFargateInstance() {
		hostname, err := getFargateHost(context.Background())
		if err == nil {
			return hostname, nil
		}
		log.Errorf("failed to get Fargate host: %v", err)
	}

	// Get the hostname via gRPC from the main agent if a hostname has not been set either from config/fargate
	hostname, err := getHostnameFromGRPC(ctx, ddgrpc.GetDDAgentClient, ipc.GetTLSClientConfig(), grpcConnectionTimeout)
	if err == nil {
		return hostname, nil
	}
	log.Errorf("failed to get hostname from grpc: %v", err)

	// If the hostname is not set then we fallback to use the agent binary
	hostname, err = getHostnameFromCmd(ddAgentBin, exec.Command)
	if err == nil {
		return hostname, nil
	}
	log.Errorf("failed to get hostname from cmd: %v", err)

	return os.Hostname()
}

type cmdFunc = func(name string, arg ...string) *exec.Cmd

// getHostnameCmd shells out to obtain the hostname used by the infra agent
func getHostnameFromCmd(ddAgentBin string, cmdFn cmdFunc) (string, error) {
	cmd := cmdFn(ddAgentBin, "hostname")

	// Copying all environment variables to child process
	// Windows: Required, so the child process can load DLLs, etc.
	// Linux:   Optional, but will make use of DD_HOSTNAME and DOCKER_DD_AGENT if they exist
	cmd.Env = append(cmd.Env, os.Environ()...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	hostname := strings.TrimSpace(stdout.String())
	if hostname == "" {
		return "", fmt.Errorf("error retrieving dd-agent hostname %s", stderr.String())
	}

	return hostname, nil
}

// getHostnameFromGRPC retrieves the hostname from the main datadog agent via GRPC
func getHostnameFromGRPC(ctx context.Context, grpcClientFn func(ctx context.Context, ipcAddress string, cmdPort string, tlsConfig *tls.Config, opts ...grpc.DialOption) (pb.AgentClient, error), tlsConfig *tls.Config, grpcConnectionTimeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, grpcConnectionTimeout)
	defer cancel()

	ipcAddress, err := pkgconfigsetup.GetIPCAddress(pkgconfigsetup.Datadog())
	if err != nil {
		return "", err
	}

	ddAgentClient, err := grpcClientFn(ctx, ipcAddress, pkgconfigsetup.GetIPCPort(), tlsConfig)
	if err != nil {
		return "", fmt.Errorf("cannot connect to datadog agent via grpc: %w", err)
	}
	reply, err := ddAgentClient.GetHostname(ctx, &pb.HostnameRequest{})
	if err != nil {
		return "", fmt.Errorf("cannot get hostname from datadog agent via grpc: %w", err)
	}

	log.Debugf("retrieved hostname:%s from datadog agent via grpc", reply.Hostname)
	return reply.Hostname, nil
}

// getContainerHostType uses the fargate library to detect container environment and returns the protobuf version of it
func getContainerHostType() model.ContainerHostType {
	switch fargate.GetOrchestrator() {
	case fargate.ECS:
		return model.ContainerHostType_fargateECS
	case fargate.EKS:
		return model.ContainerHostType_fargateEKS
	}
	return model.ContainerHostType_notSpecified
}
