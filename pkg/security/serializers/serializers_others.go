// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux && !windows

// Package serializers defines functions aiming to serialize events
package serializers

import (
	json "encoding/json"

	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

// EventSerializer serializes an event to JSON
type EventSerializer struct{}

// ToJSON returns json
func (e *EventSerializer) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// MarshalEvent marshal the event
func MarshalEvent(event *model.Event) ([]byte, error) {
	s := NewEventSerializer(event, nil)
	return json.Marshal(s)
}

// MarshalCustomEvent marshal the custom event
func MarshalCustomEvent(event *events.CustomEvent) ([]byte, error) {
	return json.Marshal(event)
}

// NewEventSerializer creates a new event serializer based on the event type
func NewEventSerializer(_ *model.Event, _ *rules.Rule) *EventSerializer {
	return nil
}
