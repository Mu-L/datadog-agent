// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package kfilters holds kfilters related files
package kfilters

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

var bpfCapabilities = rules.FieldCapabilities{
	{
		Field:       "bpf.cmd",
		TypeBitmask: eval.ScalarValueType | eval.BitmaskValueType,
	},
}

func bpfKFiltersGetter(approvers rules.Approvers) (KFilters, []eval.Field, error) {
	var (
		kfilters     []kFilter
		fieldHandled []eval.Field
	)

	for field, values := range approvers {
		switch field {
		case "bpf.cmd":
			kfilter, err := getEnumsKFilters("bpf_cmd_approvers", uintValues[uint64](values)...)
			if err != nil {
				return nil, nil, err
			}
			kfilters = append(kfilters, kfilter)
			fieldHandled = append(fieldHandled, field)
		}
	}
	return newKFilters(kfilters...), fieldHandled, nil
}
