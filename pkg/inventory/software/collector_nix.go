// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package software

// defaultCollectors returns the default collectors for production use
func defaultCollectors() []Collector {
	return []Collector{
		// todo
	}
}
