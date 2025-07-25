// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build clusterchecks

package clusterchecks

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	taggerfxmock "github.com/DataDog/datadog-agent/comp/core/tagger/fx-mock"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/version"
)

// isolateTestClcRunnerClient mocks the clcRunnersClient for advanced dispatching tests in this file only
type isolateTestClcRunnerClient struct{}

func (d *isolateTestClcRunnerClient) GetVersion(_IP string) (version.Version, error) {
	return version.Version{}, nil
}

func (d *isolateTestClcRunnerClient) GetRunnerStats(IP string) (types.CLCRunnersStats, error) {
	// Return dummy stats for nodes "A" and "B" to match the test setup
	stats := map[string]types.CLCRunnersStats{
		"A": {
			"checkA0": {AverageExecutionTime: 50, MetricSamples: 10, IsClusterCheck: true},
			"checkA1": {AverageExecutionTime: 20, MetricSamples: 10, IsClusterCheck: true},
			"checkA2": {AverageExecutionTime: 100, MetricSamples: 10, IsClusterCheck: true},
		},
		"B": {
			"checkB0": {AverageExecutionTime: 50, MetricSamples: 10, IsClusterCheck: true},
			"checkB1": {AverageExecutionTime: 20, MetricSamples: 10, IsClusterCheck: true},
			"checkB2": {AverageExecutionTime: 100, MetricSamples: 10, IsClusterCheck: true},
		},
	}
	return stats[IP], nil
}

func (d *isolateTestClcRunnerClient) GetRunnerWorkers(IP string) (types.Workers, error) {
	// Return 1 worker for node "A" and 1 worker for node "B"
	workers := map[string]types.Workers{
		"A": {Count: 1, Instances: map[string]types.WorkerInfo{"workerA": {Utilization: 0.1}}},
		"B": {Count: 1, Instances: map[string]types.WorkerInfo{"workerB": {Utilization: 0.1}}},
	}
	return workers[IP], nil
}

func TestIsolateCheckSuccessful(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	testDispatcher := newDispatcher(fakeTagger)
	testDispatcher.clcRunnersClient = &isolateTestClcRunnerClient{}
	testDispatcher.store.nodes["A"] = newNodeStore("A", "A")
	testDispatcher.store.nodes["A"].workers = pkgconfigsetup.DefaultNumWorkers
	testDispatcher.store.nodes["B"] = newNodeStore("B", "B")
	testDispatcher.store.nodes["B"].workers = pkgconfigsetup.DefaultNumWorkers

	testDispatcher.store.nodes["A"].clcRunnerStats = map[string]types.CLCRunnerStats{
		"checkA0": {
			AverageExecutionTime: 50,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA1": {
			AverageExecutionTime: 20,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA2": {
			AverageExecutionTime: 100,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
	}

	testDispatcher.store.nodes["B"].clcRunnerStats = map[string]types.CLCRunnerStats{
		"checkB0": {
			AverageExecutionTime: 50,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkB1": {
			AverageExecutionTime: 20,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkB2": {
			AverageExecutionTime: 100,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
	}
	testDispatcher.store.idToDigest = map[checkid.ID]string{
		"checkA0": "digestA0",
		"checkA1": "digestA1",
		"checkA2": "digestA2",
		"checkB0": "digestB0",
		"checkB1": "digestB1",
		"checkB2": "digestB2",
	}
	testDispatcher.store.digestToConfig = map[string]integration.Config{
		"digestA0": {},
		"digestA1": {},
		"digestA2": {},
		"digestB0": {},
		"digestB1": {},
		"digestB2": {},
	}
	testDispatcher.store.digestToNode = map[string]string{
		"digestA0": "A",
		"digestA1": "A",
		"digestA2": "A",
		"digestB0": "B",
		"digestB1": "B",
		"digestB2": "B",
	}

	response := testDispatcher.isolateCheck("checkA2")
	assert.EqualValues(t, response.CheckID, "checkA2")
	assert.EqualValues(t, response.CheckNode, "A")
	assert.True(t, response.IsIsolated)
	assert.EqualValues(t, response.Reason, "")
	assert.EqualValues(t, len(testDispatcher.store.nodes["A"].clcRunnerStats), 1)
	assert.EqualValues(t, len(testDispatcher.store.nodes["B"].clcRunnerStats), 5)
	_, containsIsolatedCheck := testDispatcher.store.nodes["A"].clcRunnerStats["checkA2"]
	assert.True(t, containsIsolatedCheck)

	requireNotLocked(t, testDispatcher.store)
}

func TestIsolateNonExistentCheckFails(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	testDispatcher := newDispatcher(fakeTagger)
	testDispatcher.clcRunnersClient = &isolateTestClcRunnerClient{}
	testDispatcher.store.nodes["A"] = newNodeStore("A", "A")
	testDispatcher.store.nodes["A"].workers = pkgconfigsetup.DefaultNumWorkers
	testDispatcher.store.nodes["B"] = newNodeStore("B", "B")
	testDispatcher.store.nodes["B"].workers = pkgconfigsetup.DefaultNumWorkers

	testDispatcher.store.nodes["A"].clcRunnerStats = map[string]types.CLCRunnerStats{
		"checkA0": {
			AverageExecutionTime: 50,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA1": {
			AverageExecutionTime: 20,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA2": {
			AverageExecutionTime: 100,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
	}

	testDispatcher.store.nodes["B"].clcRunnerStats = map[string]types.CLCRunnerStats{
		"checkB0": {
			AverageExecutionTime: 50,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkB1": {
			AverageExecutionTime: 20,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkB2": {
			AverageExecutionTime: 100,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
	}
	testDispatcher.store.idToDigest = map[checkid.ID]string{
		"checkA0": "digestA0",
		"checkA1": "digestA1",
		"checkA2": "digestA2",
		"checkB0": "digestB0",
		"checkB1": "digestB1",
		"checkB2": "digestB2",
	}
	testDispatcher.store.digestToConfig = map[string]integration.Config{
		"digestA0": {},
		"digestA1": {},
		"digestA2": {},
		"digestB0": {},
		"digestB1": {},
		"digestB2": {},
	}
	testDispatcher.store.digestToNode = map[string]string{
		"digestA0": "A",
		"digestA1": "A",
		"digestA2": "A",
		"digestB0": "B",
		"digestB1": "B",
		"digestB2": "B",
	}

	response := testDispatcher.isolateCheck("checkA5")
	assert.EqualValues(t, response.CheckID, "checkA5")
	assert.EqualValues(t, response.CheckNode, "")
	assert.False(t, response.IsIsolated)
	assert.EqualValues(t, response.Reason, "Unable to find check")
	assert.EqualValues(t, len(testDispatcher.store.nodes["A"].clcRunnerStats), 3)
	assert.EqualValues(t, len(testDispatcher.store.nodes["B"].clcRunnerStats), 3)

	requireNotLocked(t, testDispatcher.store)
}

func TestIsolateCheckOnlyOneRunnerFails(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	testDispatcher := newDispatcher(fakeTagger)
	testDispatcher.clcRunnersClient = &isolateTestClcRunnerClient{}
	testDispatcher.store.nodes["A"] = newNodeStore("A", "A")
	testDispatcher.store.nodes["A"].workers = pkgconfigsetup.DefaultNumWorkers

	testDispatcher.store.nodes["A"].clcRunnerStats = map[string]types.CLCRunnerStats{
		"checkA0": {
			AverageExecutionTime: 50,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA1": {
			AverageExecutionTime: 20,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
		"checkA2": {
			AverageExecutionTime: 100,
			MetricSamples:        10,
			IsClusterCheck:       true,
		},
	}

	testDispatcher.store.idToDigest = map[checkid.ID]string{
		"checkA0": "digestA0",
		"checkA1": "digestA1",
		"checkA2": "digestA2",
	}
	testDispatcher.store.digestToConfig = map[string]integration.Config{
		"digestA0": {},
		"digestA1": {},
		"digestA2": {},
	}
	testDispatcher.store.digestToNode = map[string]string{
		"digestA0": "A",
		"digestA1": "A",
		"digestA2": "A",
	}

	response := testDispatcher.isolateCheck("checkA1")
	assert.EqualValues(t, response.CheckID, "checkA1")
	assert.EqualValues(t, response.CheckNode, "")
	assert.False(t, response.IsIsolated)
	assert.EqualValues(t, response.Reason, "No other runners available")
	assert.EqualValues(t, len(testDispatcher.store.nodes["A"].clcRunnerStats), 3)

	requireNotLocked(t, testDispatcher.store)
}
