// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubelet || docker

package tailers

import (
	"time"

	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	auditor "github.com/DataDog/datadog-agent/comp/logs/auditor/def"
)

// isEOFCorruptedOffset return true if the offset doesn't contain a
// valid timestamp value due to a file rotation.
func isEOFCorruptedOffset(offset string) bool {
	// check if the offset value is equal to EOF char
	return len(offset) > 0 && offset[0] == 0x03
}

// since returns the date from when logs should be collected.
func since(registry auditor.Registry, identifier string) (time.Time, error) {
	var since time.Time
	var err error
	offset := registry.GetOffset(identifier)
	switch {
	case isEOFCorruptedOffset(offset):
		since = time.Time{}
	case offset != "":
		// an offset was registered, tail from the offset
		since, err = time.Parse(config.DateFormat, offset)
		if err != nil {
			since = time.Now().UTC()
		}
	default:
		// a new service has been discovered and was launched after the agent start, tail from the beginning
		since = time.Time{}
	}
	return since, err
}
