// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package env

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
)

// IsLocalAddress returns the given address if it is local or an error if it is not
func IsLocalAddress(address string) (string, error) {
	if address == "localhost" {
		return address, nil
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return "", fmt.Errorf("address was set to an invalid IP address: %s", address)
	}
	for _, cidr := range []string{
		"127.0.0.0/8", // IPv4 loopback
		"::1/128",     // IPv6 loopback
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", err
		}
		if block.Contains(ip) {
			return address, nil
		}
	}
	return "", fmt.Errorf("address was set to a non-loopback IP address: %s", address)
}

// GetIPCAddress returns the IPC address or an error if the address is not local
func GetIPCAddress(cfg pkgconfigmodel.Reader) (string, error) {
	address, err := IsLocalAddress(cfg.GetString("ipc_address"))
	if err != nil {
		return "", fmt.Errorf("ipc_address: %s", err)
	}
	return address, nil
}

// GetIPCAddressPort returns the IPC address and port, or an error if the address is not local
func GetIPCAddressPort(cfg pkgconfigmodel.Reader, portConfig string) (string, error) {
	address, err := GetIPCAddress(cfg)
	if err != nil {
		return "", err
	}

	port := cfg.GetInt(portConfig)
	if port <= 0 {
		return "", fmt.Errorf("invalid value for %s: %d", portConfig, port)
	}

	return net.JoinHostPort(address, strconv.Itoa(port)), nil
}

// GetIPCHttpsURL returns the URL for the IPC host with the given path and https scheme,
// or an error if the IPC address is not local
func GetIPCHttpsURL(cfg pkgconfigmodel.Reader, path string) (*url.URL, error) {
	return GetIPCURL(cfg, "https", "cmd_port", path)
}

// GetIPCURL returns the URL for the IPC host using the given portConfig, with the given path and scheme,
// or an error if the IPC address is not local
func GetIPCURL(cfg pkgconfigmodel.Reader, scheme, portConfig, path string) (*url.URL, error) {
	addressPort, err := GetIPCAddressPort(cfg, portConfig)
	if err != nil {
		return nil, err
	}

	ipcURL := &url.URL{
		Scheme: scheme,
		Host:   addressPort,
		Path:   path,
	}
	return ipcURL, nil
}
