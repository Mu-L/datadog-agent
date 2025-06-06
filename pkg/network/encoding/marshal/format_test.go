// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package marshal

import (
	"runtime"
	"testing"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/stretchr/testify/require"
	"go4.org/intern"

	"github.com/DataDog/datadog-agent/pkg/network"
)

func TestFormatRouteIdx(t *testing.T) {

	tests := []struct {
		desc                string
		via                 *network.Via
		routesIn, routesOut map[network.Via]RouteIdx
		idx                 int32
	}{
		{
			desc: "nil via",
			via:  nil,
			idx:  -1,
		},
		{
			desc: "empty via",
			via:  &network.Via{},
			idx:  -1,
		},
		{
			desc:     "empty routes, non-nil via",
			via:      &network.Via{Subnet: network.Subnet{Alias: "foo"}},
			idx:      0,
			routesIn: map[network.Via]RouteIdx{},
			routesOut: map[network.Via]RouteIdx{
				{Subnet: network.Subnet{Alias: "foo"}}: {Idx: 0, Route: model.Route{Subnet: &model.Subnet{Alias: "foo"}}},
			},
		},
		{
			desc: "non-empty routes, non-nil via with existing alias",
			via:  &network.Via{Subnet: network.Subnet{Alias: "foo"}},
			idx:  0,
			routesIn: map[network.Via]RouteIdx{
				{Subnet: network.Subnet{Alias: "foo"}}: {Idx: 0, Route: model.Route{Subnet: &model.Subnet{Alias: "foo"}}},
			},
			routesOut: map[network.Via]RouteIdx{
				{Subnet: network.Subnet{Alias: "foo"}}: {Idx: 0, Route: model.Route{Subnet: &model.Subnet{Alias: "foo"}}},
			},
		},
		{
			desc: "non-empty routes, non-nil via with non-existing alias",
			via:  &network.Via{Subnet: network.Subnet{Alias: "bar"}},
			idx:  1,
			routesIn: map[network.Via]RouteIdx{
				{Subnet: network.Subnet{Alias: "foo"}}: {Idx: 0, Route: model.Route{Subnet: &model.Subnet{Alias: "foo"}}},
			},
			routesOut: map[network.Via]RouteIdx{
				{Subnet: network.Subnet{Alias: "foo"}}: {Idx: 0, Route: model.Route{Subnet: &model.Subnet{Alias: "foo"}}},
				{Subnet: network.Subnet{Alias: "bar"}}: {Idx: 1, Route: model.Route{Subnet: &model.Subnet{Alias: "bar"}}},
			},
		},
		{
			desc:     "with interface mac address",
			via:      &network.Via{Interface: network.Interface{HardwareAddr: "ab:cd:ef:00:11:22"}},
			idx:      0,
			routesIn: map[network.Via]RouteIdx{},
			routesOut: map[network.Via]RouteIdx{
				{Interface: network.Interface{HardwareAddr: "ab:cd:ef:00:11:22"}}: {Idx: 0, Route: model.Route{Interface: &model.Interface{HardwareAddr: "ab:cd:ef:00:11:22"}}},
			},
		},
	}

	for _, te := range tests {
		t.Run(te.desc, func(t *testing.T) {
			idx := formatRouteIdx(te.via, te.routesIn)
			require.Equal(t, te.idx, idx)
			require.Len(t, te.routesIn, len(te.routesIn), "routes in and out are not equal, expected: %v, actual: %v", te.routesOut, te.routesIn)
			for k, v := range te.routesOut {
				otherv, ok := te.routesIn[k]
				require.True(t, ok, "routes in and out are not equal, expected: %v, actual: %v", te.routesOut, te.routesIn)
				require.Equal(t, v, otherv, "routes in and out are not equal, expected: %v, actual: %v", te.routesOut, te.routesIn)
			}
		})
	}
}

func BenchmarkConnectionReset(b *testing.B) {
	c := new(model.Connection)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Reset()
	}
	runtime.KeepAlive(c)
}

func BenchmarkFormatTags(b *testing.B) {
	tagSet := network.NewTagsSet()
	var c network.ConnectionStats
	c.Tags = []*intern.Value{
		intern.GetByString("env:env"),
		intern.GetByString("version:version"),
		intern.GetByString("service:service"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		formatTags(c, tagSet, nil)
	}
}
