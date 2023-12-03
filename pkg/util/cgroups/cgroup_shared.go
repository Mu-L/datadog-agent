// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package cgroups

import (
	"strconv"
)

const (
	cgroupProcsFile = "cgroup.procs"
	procCgroupFile  = "cgroup"
)

// ParseCPUSetFormat counts CPUs in CPUSet specs like "0,1,5-8". These are comma-separated lists
// of processor IDs, with hyphenated ranges representing closed sets.
// So "0,1,5-8" represents processors 0, 1, 5, 6, 7, 8.
// The function returns the count of CPUs, in this case 6.
func ParseCPUSetFormat(line string) uint64 {
	var numCPUs uint64
	lineRaw := []byte(line)

	var p0, p1 uint64
	var hyphenated bool

	for i, v := range lineRaw {
		if v == byte('-') {
			hyphenated = true
			continue
		}

		if v != byte(',') {
			val, _ := strconv.Atoi(string(v))

			if hyphenated {
				p1 *= 10
				p1 += uint64(val)
			} else {
				p0 *= 10
				p0 += uint64(val)
			}
		}

		// add to cpu count there is a comma or this is the last cpu value
		if v == byte(',') || i == len(lineRaw)-1 {
			if hyphenated {
				numCPUs += p1 - p0 + 1
			} else {
				numCPUs++
			}
			// reset
			p0, p1 = 0, 0
			hyphenated = false
		}
	}

	return numCPUs
}

func nilIfZero(value **uint64) {
	if *value != nil && **value == 0 {
		*value = nil
	}
}
