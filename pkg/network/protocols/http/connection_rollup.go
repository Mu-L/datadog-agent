// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package http

import (
	"github.com/DataDog/datadog-agent/pkg/network/types"
)

type ipTuple struct {
	al uint64
	ah uint64
	bl uint64
	bh uint64
}

type ephemeralPortSide uint8

const (
	ephemeralPortUnknown = iota
	ephemeralPortA
	ephemeralPortB
)

type portValues struct {
	// these two values are populated by the *first* connection
	// that has a given ipTuple
	a uint16
	b uint16

	// this value is determined by analyzing the second connection that matches
	// the associated ipTuple but has either a different port "a" or "b"
	ephemeralSide ephemeralPortSide

	// this is to determine whether we should generate (a, b) or (b, a) when
	// calling generateKey()
	flipped bool
}

type ConnectionAggregator struct {
	data map[ipTuple]portValues
}

func NewConnectionAggregator() *ConnectionAggregator {
	return &ConnectionAggregator{
		data: make(map[ipTuple]portValues, 1000),
	}
}

func (c ConnectionAggregator) GetTranslatedKey(key types.ConnectionKey) types.ConnectionKey {
	// order IPs and ports such that
	// srcIP < dstIP
	//
	// why do we do this? our kernel code does a best-effort in ordering tuples
	// based on the *port* number, but this may produce tuples that look like
	//
	// A:5000 B:8080
	// B:8080 B:9000
	//
	// If either host(A) or host(B) don't really "abide" to the correct port
	// ranges. Because IPs for the same pair of services can be eventually
	// flipped, we make sure to order them by IPs here.
	normalizedKey, flipped := normalizeByIP(key)

	ips, ports := split(normalizedKey)
	savedPorts, ok := c.data[ips]
	if !ok {
		// first time we see this ipTuple, so we just save the IPs and ports as
		// we can't know which side has the ephemeral port yet.  note that this
		// key will be returned for future connections that have match
		// everything but one port:
		//
		// So let's say we see first:
		// c1: A:6000 B:80
		// And then:
		// c2: A:6001 B:80
		// Or even:
		// c3: B:80 A:6002
		//
		// What we'll see is the following:
		//
		// GetTranslatedKey(c1) => c1
		// GetTranslatedKey(c2) => c1
		// GetTranslatedKey(c3) => c1
		ports.flipped = flipped
		c.data[ips] = ports
		return key
	}

	if savedPorts.a == ports.a && savedPorts.b == ports.b {
		// we're seeing the same connection for a second time, so we bail out
		// earlier.
		// the only reason why we call `generateKey` (as opposed to just `return key`)
		// is because we want to make sure that if we first saw (A:X, B:Y)
		// and then (B:Y, A:X), we'll preserve the original key ordering (A:X, B:Y)
		return generateKey(ips, savedPorts)
	}

	if savedPorts.a != ports.a && savedPorts.b != ports.b {
		// this is more like an edge-case but it may happen. in this case we
		// don't attempt to translate the key because we would be likely be
		// merging two connections that are hitting different services
		// we're talking about something like:
		//
		// c1: A:X B:Y
		// c2: A:Z B:W
		//
		// So none of the ports match and we preserve the key as it is.
		return key
	}

	if savedPorts.ephemeralSide == ephemeralPortUnknown {
		// determine which side is the ephemeral port, in case we haven't done it yet
		// this information is only used when calling `RedactEphemeralPort()`
		if savedPorts.a == ports.a {
			savedPorts.ephemeralSide = ephemeralPortB
		} else {
			savedPorts.ephemeralSide = ephemeralPortA
		}

		c.data[ips] = savedPorts
	}

	return generateKey(ips, savedPorts)
}

func (c ConnectionAggregator) RedactEphemeralPort(key types.ConnectionKey) types.ConnectionKey {
	normalizedKey, flipped := normalizeByIP(key)
	ips, _ := split(normalizedKey)
	savedPorts, ok := c.data[ips]
	if !ok || savedPorts.ephemeralSide == ephemeralPortUnknown {
		// We either have seen at all this connection, or weren't able to
		// determine the ephemeral port side. In that case we return the key
		// completely unmodified.
		return key
	}

	if savedPorts.ephemeralSide == ephemeralPortA {
		savedPorts.a = 0
	} else {
		savedPorts.b = 0
	}

	newKey := generateKey(ips, savedPorts)
	if flipped != savedPorts.flipped {
		// this is just to ensure that we preserve the tuple order of the
		// function argument
		newKey = flipKey(newKey)
	}

	return newKey
}

// normalizeByIP such that srcIP < dstIP
func normalizeByIP(key types.ConnectionKey) (normalizedKey types.ConnectionKey, flipped bool) {
	if key.SrcIPHigh > key.DstIPHigh || (key.SrcIPHigh == key.DstIPHigh && key.SrcIPLow > key.DstIPLow) {
		return flipKey(key), true
	}

	return key, false
}

func split(key types.ConnectionKey) (ipTuple, portValues) {
	ips := ipTuple{
		al: key.SrcIPLow,
		ah: key.SrcIPHigh,
		bl: key.DstIPLow,
		bh: key.DstIPHigh,
	}

	ports := portValues{
		a: key.SrcPort,
		b: key.DstPort,
	}

	return ips, ports
}

func generateKey(ips ipTuple, ports portValues) types.ConnectionKey {
	key := types.ConnectionKey{
		SrcIPLow:  ips.al,
		SrcIPHigh: ips.ah,
		DstIPLow:  ips.bl,
		DstIPHigh: ips.bh,
		SrcPort:   ports.a,
		DstPort:   ports.b,
	}

	if ports.flipped {
		key = flipKey(key)
	}

	return key
}

func flipKey(key types.ConnectionKey) types.ConnectionKey {
	return types.ConnectionKey{
		SrcIPLow:  key.DstIPLow,
		SrcIPHigh: key.DstIPHigh,
		DstIPLow:  key.SrcIPLow,
		DstIPHigh: key.SrcIPHigh,
		SrcPort:   key.DstPort,
		DstPort:   key.SrcPort,
	}
}
