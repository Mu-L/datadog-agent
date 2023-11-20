// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package api

import (
	"net"

	"github.com/DataDog/datadog-agent/pkg/config"
)

// newListener creates a listening connection
func newListener() (net.Listener, error) {
	addressPort, err := config.GetIPCAddressPort("security_agent.cmd_port")
	if err != nil {
		return nil, err
	}
	return net.Listen("tcp", addressPort)
}
