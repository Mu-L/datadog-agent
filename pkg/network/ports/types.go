// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package ports provides utilities for working with network ports, including
// ephemeral range detection and various port-related operations.
package ports

// EphemeralPortType will be either EphemeralUnknown, EphemeralTrue, EphemeralFalse
type EphemeralPortType uint8

const (
	// EphemeralUnknown indicates inability to determine whether the port is in the ephemeral range or not
	EphemeralUnknown EphemeralPortType = 0

	// EphemeralTrue means the port has been detected to be in the configured ephemeral range
	EphemeralTrue EphemeralPortType = 1

	// EphemeralFalse means the port has been detected to not be in the configured ephemeral range
	EphemeralFalse EphemeralPortType = 2
)

func (e EphemeralPortType) String() string {
	switch e {
	case EphemeralTrue:
		return "ephemeral"
	case EphemeralFalse:
		return "not ephemeral"
	default:
		return "unspecified"
	}
}

// The types below are mostly duplicates of `network` to avoid a problem of
// circular dependency. Currently the code present in this package is required
// by:
//
// (a) pkg/network
// (b) pkg/protocols/http
//
// The issue is that (a) includes (b) as well, and therefore (b) can't rely on types defined by
// (a).
//
// In the near future we should perhaps consider moving some of the main
// `network` type definitions to a dedicated package to avoid this type of
// problem.

// ConnectionType will be either TCP or UDP
type ConnectionType uint8

const (
	// TCP connection type
	TCP ConnectionType = 0
	// UDP connection type
	UDP ConnectionType = 1
)

func (c ConnectionType) String() string {
	if c == TCP {
		return "TCP"
	}
	return "UDP"
}

const (
	// AFINET represents v4 connections
	AFINET ConnectionFamily = 0
	// AFINET6 represents v6 connections
	AFINET6 ConnectionFamily = 1
)

// ConnectionFamily will be either v4 or v6
type ConnectionFamily uint8
