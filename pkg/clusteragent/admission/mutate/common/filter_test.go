// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFailingInjectionConfig(t *testing.T) {
	tests := []struct {
		name string

		instrumentationEnabled                bool
		enabledNamespaces, disabledNamespaces []string

		expectedFilterError, expectedWebhookError bool
		expectedNamespaces                        map[string]bool
	}{
		{
			name: "disabled",
			expectedNamespaces: map[string]bool{
				"enabled-ns":   false,
				"disabled-ns":  false,
				"any-other-ns": false,
			},
		},
		{
			name:                   "enabled no namespaces",
			instrumentationEnabled: true,
			expectedNamespaces: map[string]bool{
				"enabled-ns":   true,
				"disabled-ns":  true,
				"any-other-ns": true,
			},
		},
		{
			name:                   "enabled with enabled namespace",
			instrumentationEnabled: true,
			enabledNamespaces:      []string{"enabled-ns"},
			expectedNamespaces: map[string]bool{
				"enabled-ns":   true,
				"disabled-ns":  false,
				"any-other-ns": false,
			},
		},
		{
			name:                   "enabled with disabled namespace",
			instrumentationEnabled: true,
			disabledNamespaces:     []string{"disabled-ns"},
			expectedNamespaces: map[string]bool{
				"enabled-ns":   true,
				"disabled-ns":  false,
				"any-other-ns": true,
			},
		},
		{
			name:                   "both enabled and disabled errors, fail closed",
			instrumentationEnabled: true,
			enabledNamespaces:      []string{"enabled-ns"},
			disabledNamespaces:     []string{"disabled-ns"},
			expectedFilterError:    true,
			expectedNamespaces: map[string]bool{
				"enabled-ns":   false,
				"disabled-ns":  false,
				"any-other-ns": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsFilter, _ := NewDefaultFilter(tt.instrumentationEnabled, tt.enabledNamespaces, tt.disabledNamespaces)
			require.NotNil(t, nsFilter, "we should always get a filter")

			checkedNamespaces := map[string]bool{}
			for ns := range tt.expectedNamespaces {
				checkedNamespaces[ns] = nsFilter.IsNamespaceEligible(ns)
			}

			require.Equal(t, tt.expectedNamespaces, checkedNamespaces)
		})
	}
}
