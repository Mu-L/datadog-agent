// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package worker

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	haagentmock "github.com/DataDog/datadog-agent/comp/haagent/mock"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	"github.com/DataDog/datadog-agent/pkg/collector/check/stats"
	"github.com/DataDog/datadog-agent/pkg/collector/check/stub"
	"github.com/DataDog/datadog-agent/pkg/collector/runner/expvars"
	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/config/model"
)

type stubCheck struct {
	stub.StubCheck
	id string
}

func (c *stubCheck) ID() checkid.ID { return checkid.ID(c.id) }
func (c *stubCheck) String() string { return checkid.IDToCheckName(c.ID()) }

func newTestCheck(id string) *stubCheck {
	return &stubCheck{id: id}
}

func addExpvarsCheckStats(c check.Check) {
	expvars.AddCheckStats(c, 0, nil, nil, stats.SenderStats{}, haagentmock.NewMockHaAgent())
}

func setUp(cfg model.Config) {
	cfg.SetWithoutSource(loggingFrequencyConfigKey, "20")
	expvars.Reset()
}

func TestShouldLogNewCheck(t *testing.T) {
	mockConfig := configmock.New(t)
	setUp(mockConfig)

	for idx := 0; idx < 10; idx++ {
		fakeID := checkid.ID(fmt.Sprintf("testcheck %d", idx))

		shouldLog, lastVerboseLog := shouldLogCheck(fakeID)

		assert.True(t, shouldLog)
		assert.False(t, lastVerboseLog)
	}
}

func TestShouldLogLastVerboseLog(t *testing.T) {
	mockConfig := configmock.New(t)
	setUp(mockConfig)

	for idx := 1; idx < 10; idx++ {
		testCheck := newTestCheck(fmt.Sprintf("testcheck %d", idx))

		for logIdx := 1; logIdx < 61; logIdx++ {
			// Given a CheckLogger
			checkLogger := CheckLogger{Check: testCheck}
			// When I start the check
			checkLogger.CheckStarted()
			// And increment the CheckStats
			addExpvarsCheckStats(testCheck)
			// And the check finishes
			checkLogger.CheckFinished()

			lastVerboseLog := checkLogger.lastVerboseLog
			shouldLog := checkLogger.shouldLog

			// Then lastVerboseLog should be true for 5th run
			// And shouldLog should be true as well so that we log the next run message
			// initialCheckLoggingSeriesLimit should be 5
			if logIdx == 5 {
				assert.True(t, lastVerboseLog, fmt.Sprintf("Loop idx: %d", logIdx))
				assert.True(t, shouldLog, fmt.Sprintf("Loop idx: %d", logIdx))
			} else {
				assert.False(t, lastVerboseLog, fmt.Sprintf("Loop idx: %d", logIdx))
			}
		}
	}
}

func TestShouldLogInitialCheckLoggingSeries(t *testing.T) {
	mockConfig := configmock.New(t)
	setUp(mockConfig)

	for idx := 0; idx < 5; idx++ {
		testCheck := newTestCheck(fmt.Sprintf("testcheck %d", idx))

		for logIdx := 1; logIdx < 61; logIdx++ {
			// Given a CheckLogger
			checkLogger := CheckLogger{Check: testCheck}
			// When I start the check
			checkLogger.CheckStarted()
			// And increment the CheckStats
			addExpvarsCheckStats(testCheck)
			// And the check finishes
			checkLogger.CheckFinished()

			shouldLog := checkLogger.shouldLog

			// Then shouldLog should be true for first five runs and every 20th run
			// initialCheckLoggingSeriesLimit is 5 and we use 20 as our log limit config value in tests
			if logIdx <= 5 || logIdx%20 == 0 {
				assert.True(t, shouldLog, fmt.Sprintf("Loop idx: %d", logIdx))
			} else {
				assert.False(t, shouldLog, fmt.Sprintf("Loop idx: %d", logIdx))
			}
		}
	}
}
