// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/fx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/flare/helpers"
	logmock "github.com/DataDog/datadog-agent/comp/core/log/mock"
	"github.com/DataDog/datadog-agent/pkg/serializer/marshaler"
	serializermock "github.com/DataDog/datadog-agent/pkg/serializer/mocks"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Payload handles the JSON unmarshalling of the metadata payload
type testPayload struct{}

func (p *testPayload) MarshalJSON() ([]byte, error) {
	return []byte("{\"test\": true}"), nil
}

func (p *testPayload) SplitPayload(_ int) ([]marshaler.AbstractMarshaler, error) {
	return nil, fmt.Errorf("could not split inventories agent payload any more, payload is too big for intake")
}

func getTestInventoryPayload(t *testing.T, confOverrides map[string]any) *InventoryPayload {
	i := CreateInventoryPayload(
		fxutil.Test[config.Component](t, config.MockModule(), fx.Replace(config.MockParams{Overrides: confOverrides})),
		logmock.New(t),
		serializermock.NewMetricSerializer(t),
		func() marshaler.JSONMarshaler { return &testPayload{} },
		"test.json",
	)
	return &i
}

func getEmptyInventoryPayload(t *testing.T, confOverrides map[string]any) *InventoryPayload {
	i := CreateInventoryPayload(
		fxutil.Test[config.Component](t, config.MockModule(), fx.Replace(config.MockParams{Overrides: confOverrides})),
		logmock.New(t),
		serializermock.NewMetricSerializer(t),
		func() marshaler.JSONMarshaler { return nil },
		"testempty.json",
	)
	return &i
}

func TestEnabled(t *testing.T) {
	i := getTestInventoryPayload(t, map[string]any{
		"inventories_enabled": true,
	})

	assert.True(t, i.Enabled)
}

func TestDisabled(t *testing.T) {
	i := getTestInventoryPayload(t, map[string]any{
		"inventories_enabled": false,
	})

	assert.False(t, i.Enabled)
}

func TestDefaultInterval(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	assert.Equal(t, defaultMinInterval, i.MinInterval)
	assert.Equal(t, defaultMaxInterval, i.MaxInterval)
}

func TestInterval(t *testing.T) {
	i := getTestInventoryPayload(t, map[string]any{
		"inventories_min_interval": 123,
		"inventories_max_interval": 456,
	})

	assert.Equal(t, 123*time.Second, i.MinInterval)
	assert.Equal(t, 456*time.Second, i.MaxInterval)
}

func TestMetadataProvider(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	i.Enabled = true
	assert.NotNil(t, i.MetadataProvider().Callback)

	i.Enabled = false
	assert.Nil(t, i.MetadataProvider().Callback)
}

func TestFlareProvider(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	assert.NotNil(t, i.FlareProvider().FlareFiller.Callback)
}

func TestGetAsJSON(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	i.Enabled = false
	_, err := i.GetAsJSON()
	assert.Error(t, err)
}

func TestFillFlare(t *testing.T) {
	f := helpers.NewFlareBuilderMock(t, false)
	i := getTestInventoryPayload(t, nil)

	i.Enabled = false
	i.fillFlare(f)
	f.AssertFileExists("metadata", "inventory", "test.json")
	f.AssertFileContent("inventory metadata is disabled", "metadata", "inventory", "test.json")

	i.Enabled = true
	i.fillFlare(f)
	f.AssertFileExists("metadata", "inventory", "test.json")
	f.AssertFileContent("{\n    \"test\": true\n}", "metadata", "inventory", "test.json")
}

func TestCollectRecentLastCollect(t *testing.T) {
	i := getTestInventoryPayload(t, nil)
	i.LastCollect = time.Now()
	i.createdAt = time.Now().Add(-2 * time.Minute)

	interval := i.collect(context.Background())
	assert.Equal(t, defaultMinInterval, interval)
	// check that no Payload was send since LastCollect is recent
	i.serializer.(*serializermock.MetricSerializer).AssertExpectations(t)
}

func TestCollectStartupTime(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	// testing collect do not send metadata if hasn't elapsed a minute from createdAt time
	createdAt := time.Now().Add(2 * time.Minute)
	i.createdAt = createdAt

	serializerMock := i.serializer.(*serializermock.MetricSerializer)
	duration := 1 * time.Minute

	interval := i.collect(context.Background())
	assert.Equal(t, duration-time.Since(createdAt).Round(duration), interval.Round(duration))
	assert.Empty(t, serializerMock.Calls)

	// testing with custom values from configuration
	i = getTestInventoryPayload(t, map[string]any{
		"inventories_first_run_delay": 0,
	})

	// reset serializer mock
	serializerMock = serializermock.NewMetricSerializer(t)

	serializerMock.On(
		"SendMetadata",
		mock.MatchedBy(func(m marshaler.JSONMarshaler) bool {
			if _, ok := m.(*testPayload); !ok {
				return false
			}
			return true
		})).Return(nil)

	i.serializer = serializerMock
	interval = i.collect(context.Background())
	assert.Equal(t, defaultMinInterval, interval)
	serializerMock.AssertExpectations(t)
}

func TestCollect(t *testing.T) {
	i := getTestInventoryPayload(t, nil)

	// Ensure calls to collect do not fail the check for createdAt
	i.createdAt = time.Now().Add(-2 * time.Minute)

	serializerMock := i.serializer.(*serializermock.MetricSerializer)

	// testing collect with LastCollect > MaxInterval

	serializerMock.On(
		"SendMetadata",
		mock.MatchedBy(func(m marshaler.JSONMarshaler) bool {
			if _, ok := m.(*testPayload); !ok {
				return false
			}
			return true
		})).Return(nil)

	// Make sure the minInterval between two payload has expired
	i.LastCollect = time.Now().Add(-1 * time.Hour)

	now := time.Now()
	interval := i.collect(context.Background())
	assert.Equal(t, defaultMinInterval, interval)
	assert.False(t, i.LastCollect.Before(now))
	i.serializer.(*serializermock.MetricSerializer).AssertExpectations(t)

	// testing collect with LastCollect between MinInterval and MaxInterval

	// reset serializer mock and test that a new call to Collect doesn't trigger a new payload
	serializerMock = serializermock.NewMetricSerializer(t)
	i.serializer = serializerMock

	i.LastCollect = time.Now().Add(-i.MinInterval + 1*time.Second)
	i.collect(context.Background())
	i.serializer.(*serializermock.MetricSerializer).AssertExpectations(t)

	// testing collect with LastCollect between MinInterval and MaxInterval with forceRefresh being trigger

	i.Refresh()
	assert.True(t, i.forceRefresh.Load())

	serializerMock.On(
		"SendMetadata",
		mock.MatchedBy(func(m marshaler.JSONMarshaler) bool {
			if _, ok := m.(*testPayload); !ok {
				return false
			}
			return true
		})).Return(nil)

	i.collect(context.Background())
	i.serializer.(*serializermock.MetricSerializer).AssertExpectations(t)
	assert.False(t, i.forceRefresh.Load())
}

func TestCollectEmptyPayload(t *testing.T) {
	i := getEmptyInventoryPayload(t, nil)

	// Ensure calls to collect do not fail the check for createdAt
	i.createdAt = time.Now().Add(-2 * time.Minute)
	// Make sure the minInterval between two payload has expired
	i.LastCollect = time.Now().Add(-1 * time.Hour)

	now := time.Now()
	interval := i.collect(context.Background())
	assert.Equal(t, defaultMinInterval, interval)
	assert.False(t, i.LastCollect.Before(now))
	i.serializer.(*serializermock.MetricSerializer).AssertNotCalled(t, "SendMetadata")
}
