// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build clusterchecks

package clusterchecks

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	taggerfxmock "github.com/DataDog/datadog-agent/comp/core/tagger/fx-mock"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	"github.com/DataDog/datadog-agent/pkg/config/env"
	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/clustername"
	"github.com/DataDog/datadog-agent/pkg/version"
)

func generateIntegration(name string) integration.Config {
	return integration.Config{
		Name:         name,
		ClusterCheck: true,
	}
}

func generateEndpointsIntegration(name, nodename string, metricsExcluded bool) integration.Config {
	return integration.Config{
		Name:            name,
		ClusterCheck:    true,
		NodeName:        nodename,
		MetricsExcluded: metricsExcluded,
	}
}

func extractCheckNames(configs []integration.Config) []string {
	var names []string
	for _, c := range configs {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

func TestScheduleUnschedule(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	stored, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 0)

	config1 := integration.Config{
		Name:         "non-cluster-check",
		ClusterCheck: false,
	}
	config2 := integration.Config{
		Name:         "cluster-check",
		ClusterCheck: true,
	}

	dispatcher.Schedule([]integration.Config{config1, config2})
	stored, err = dispatcher.getAllConfigs()
	assert.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, "cluster-check", stored[0].Name)
	assert.Equal(t, 1, len(dispatcher.store.danglingConfigs))

	dispatcher.Unschedule([]integration.Config{config1, config2})
	stored, err = dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 0)
	assert.Equal(t, 0, len(dispatcher.store.danglingConfigs))

	requireNotLocked(t, dispatcher.store)
}

func TestScheduleUnscheduleEndpoints(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	config1 := generateIntegration("cluster-check")
	config2 := generateEndpointsIntegration("endpoints-check1", "node1", false)

	// Should schedule config2 only
	dispatcher.Schedule([]integration.Config{config1, config2})
	assert.Equal(t, 1, len(dispatcher.store.endpointsConfigs["node1"]))

	dispatcher.Unschedule([]integration.Config{config1, config2})
	assert.Equal(t, 0, len(dispatcher.store.endpointsConfigs["node1"]))

	requireNotLocked(t, dispatcher.store)
}

func TestExcludeEndpoint(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	config1 := generateEndpointsIntegration("endpoints-check1", "node1", true)
	config2 := generateEndpointsIntegration("endpoints-check2", "node2", false)

	// Should schedule config2 only
	dispatcher.Schedule([]integration.Config{config1, config2})
	assert.Equal(t, 1, len(dispatcher.store.endpointsConfigs["node2"]))

	requireNotLocked(t, dispatcher.store)
}

func TestScheduleReschedule(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	config := generateIntegration("cluster-check")

	// Register to node1
	dispatcher.addConfig(config, "node1")
	configs1, _, err := dispatcher.getClusterCheckConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs1, 1)
	assert.Contains(t, configs1, config)

	// Move to node2
	dispatcher.addConfig(config, "node2")
	configs2, _, err := dispatcher.getClusterCheckConfigs("node2")
	assert.NoError(t, err)
	assert.Len(t, configs2, 1)
	assert.Contains(t, configs2, config)

	// De-registered from previous node
	configs1, _, err = dispatcher.getClusterCheckConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs1, 0)

	// Only registered once in global list
	stored, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 1)
	assert.Contains(t, stored, config)

	requireNotLocked(t, dispatcher.store)
}

func TestScheduleRescheduleEndpoints(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	config := generateEndpointsIntegration("endpoints-check1", "node1", false)

	// Register to node1
	dispatcher.addEndpointConfig(config, "node1")
	configs1, err := dispatcher.getEndpointsConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs1, 1)
	assert.Contains(t, configs1, config)

	// Register another config to node1
	config = generateEndpointsIntegration("endpoints-check2", "node1", false)
	dispatcher.addEndpointConfig(config, "node1")
	configs2, err := dispatcher.getEndpointsConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs2, 2)
	assert.Len(t, dispatcher.store.endpointsConfigs["node1"], 2)
	assert.Contains(t, configs2, config)

	// Register config to node2
	config = generateEndpointsIntegration("endpoints-check3", "node3", false)
	dispatcher.addEndpointConfig(config, "node3")
	configs2, err = dispatcher.getEndpointsConfigs("node3")
	assert.NoError(t, err)
	assert.Len(t, configs2, 1)
	assert.Contains(t, configs2, config)

	requireNotLocked(t, dispatcher.store)
}

func TestDescheduleRescheduleSameNode(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	config := generateIntegration("cluster-check")

	// Schedule to node1
	dispatcher.addConfig(config, "node1")
	configs1, _, err := dispatcher.getClusterCheckConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs1, 1)
	assert.Contains(t, configs1, config)

	// Deschedule
	dispatcher.removeConfig(config.Digest())
	stored, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 0)

	// Re-schedule to node1
	dispatcher.addConfig(config, "node1")
	configs2, _, err := dispatcher.getClusterCheckConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs2, 1)
	assert.Contains(t, configs2, config)

	// Only registered once in global list
	stored, err = dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 1)
	assert.Contains(t, stored, config)

	requireNotLocked(t, dispatcher.store)
}

func TestGetNodeTypeCounts(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// Register 2 CLC runners and 3 node agents
	dispatcher.processNodeStatus("runner1", "10.0.0.10", types.NodeStatus{LastChange: 1, NodeType: types.NodeTypeCLCRunner})
	dispatcher.processNodeStatus("runner2", "10.0.0.11", types.NodeStatus{LastChange: 2, NodeType: types.NodeTypeCLCRunner})
	dispatcher.processNodeStatus("agent1", "10.0.0.20", types.NodeStatus{LastChange: 3, NodeType: types.NodeTypeNodeAgent})
	dispatcher.processNodeStatus("agent2", "10.0.0.21", types.NodeStatus{LastChange: 4, NodeType: types.NodeTypeNodeAgent})
	dispatcher.processNodeStatus("agent3", "10.0.0.22", types.NodeStatus{LastChange: 5, NodeType: types.NodeTypeNodeAgent})

	clcRunnerCount, nodeAgentCount := dispatcher.store.CountNodeTypes()
	assert.Equal(t, 2, clcRunnerCount)
	assert.Equal(t, 3, nodeAgentCount)
}

func TestProcessNodeStatus(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	status1 := types.NodeStatus{LastChange: 10}

	// Warmup phase, upToDate is unconditionally true
	upToDate := dispatcher.processNodeStatus("node1", "10.0.0.1", status1)
	assert.True(t, upToDate)
	node1, found := dispatcher.store.getNodeStore("node1")
	assert.True(t, found)
	assert.True(t, timestampNow() >= node1.heartbeat)
	assert.True(t, timestampNow() <= node1.heartbeat+1)

	// Warmup is finished, timestamps differ
	dispatcher.store.active = true
	upToDate = dispatcher.processNodeStatus("node1", "10.0.0.1", status1)
	assert.False(t, upToDate)

	// Give changes
	node1.lastConfigChange = timestampNowNano()
	node1.heartbeat = node1.heartbeat - 50
	status2 := types.NodeStatus{LastChange: node1.lastConfigChange - 2}
	upToDate = dispatcher.processNodeStatus("node1", "10.0.0.1", status2)
	assert.False(t, upToDate)
	assert.True(t, timestampNow() >= node1.heartbeat)
	assert.True(t, timestampNow() <= node1.heartbeat+1)

	// No change
	status3 := types.NodeStatus{LastChange: node1.lastConfigChange}
	upToDate = dispatcher.processNodeStatus("node1", "10.0.0.1", status3)
	assert.True(t, upToDate)

	// Change clientIP
	upToDate = dispatcher.processNodeStatus("node1", "10.0.0.2", status3)
	assert.True(t, upToDate)
	node1, found = dispatcher.store.getNodeStore("node1")
	assert.True(t, found)
	assert.Equal(t, "10.0.0.2", node1.clientIP)

	requireNotLocked(t, dispatcher.store)
}

func TestGetNodeWithLessChecks(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// No node registered -> empty string
	assert.Equal(t, "", dispatcher.getNodeWithLessChecks())

	// 1 config on node1, 2 on node2
	dispatcher.addConfig(generateIntegration("A"), "node1")
	dispatcher.addConfig(generateIntegration("B"), "node2")
	dispatcher.addConfig(generateIntegration("C"), "node2")
	assert.Equal(t, "node1", dispatcher.getNodeWithLessChecks())

	// 3 configs on node1, 2 on node2
	dispatcher.addConfig(generateIntegration("D"), "node1")
	dispatcher.addConfig(generateIntegration("E"), "node1")
	assert.Equal(t, "node2", dispatcher.getNodeWithLessChecks())

	// Add an empty node3
	dispatcher.processNodeStatus("node3", "10.0.0.3", types.NodeStatus{})
	assert.Equal(t, "node3", dispatcher.getNodeWithLessChecks())

	requireNotLocked(t, dispatcher.store)
}

func TestExpireNodes(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// Node with no status (bug ?), handled by expiration
	dispatcher.addConfig(generateIntegration("one"), "node1")
	assert.Equal(t, 1, len(dispatcher.store.nodes))
	dispatcher.expireNodes()
	assert.Equal(t, 0, len(dispatcher.store.nodes))
	assert.Equal(t, 1, len(dispatcher.store.danglingConfigs))

	// Nodes with valid statuses
	dispatcher.store.clearDangling()
	dispatcher.addConfig(generateIntegration("A"), "nodeA")
	dispatcher.addConfig(generateIntegration("B1"), "nodeB")
	dispatcher.addConfig(generateIntegration("B2"), "nodeB")
	dispatcher.processNodeStatus("nodeA", "10.0.0.1", types.NodeStatus{})
	dispatcher.processNodeStatus("nodeB", "10.0.0.2", types.NodeStatus{})
	assert.Equal(t, 2, len(dispatcher.store.nodes))

	// Fake the status report timestamps, nodeB should expire
	dispatcher.store.nodes["nodeA"].heartbeat = timestampNow() - 25
	dispatcher.store.nodes["nodeB"].heartbeat = timestampNow() - 35

	assert.Equal(t, 0, len(dispatcher.store.danglingConfigs))
	dispatcher.expireNodes()
	assert.Equal(t, 1, len(dispatcher.store.nodes))
	assert.Equal(t, 2, len(dispatcher.store.danglingConfigs))

	requireNotLocked(t, dispatcher.store)
}

func TestRescheduleDanglingFromExpiredNodes(t *testing.T) {
	// This test case can represent a rollout of the cluster check workers
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// Register a node with a correct status & schedule a Check
	dispatcher.processNodeStatus("nodeA", "10.0.0.1", types.NodeStatus{})
	dispatcher.Schedule([]integration.Config{
		generateIntegration("A"),
	})

	// Ensure it's dispatch correctly
	allConfigs, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(allConfigs))
	assert.Equal(t, []string{"A"}, extractCheckNames(allConfigs))

	// Ensure it's running correctly
	configsA, _, err := dispatcher.getClusterCheckConfigs("nodeA")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(configsA))

	// Expire NodeA
	dispatcher.store.nodes["nodeA"].heartbeat = timestampNow() - 35

	// Assert config becomes dangling when we trigger a expireNodes.
	assert.Equal(t, 0, len(dispatcher.store.danglingConfigs))
	dispatcher.expireNodes()
	assert.Equal(t, 0, len(dispatcher.store.nodes))
	assert.Equal(t, 1, len(dispatcher.store.danglingConfigs))

	requireNotLocked(t, dispatcher.store)

	// Register new node as healthy
	dispatcher.processNodeStatus("nodeB", "10.0.0.2", types.NodeStatus{})

	// Ensure we have 1 dangling to schedule, as new available node is registered
	assert.True(t, dispatcher.shouldDispatchDangling())
	configs := dispatcher.retrieveDangling()
	// Assert the check is scheduled
	scheduledIDs := dispatcher.reschedule(configs)
	dispatcher.deleteDangling(scheduledIDs)
	danglingConfig, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(danglingConfig))
	assert.Equal(t, []string{"A"}, extractCheckNames(danglingConfig))

	// Make sure make sure the dangling check is rescheduled on the new node
	configsB, _, err := dispatcher.getClusterCheckConfigs("nodeB")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(configsB))
}

func TestDispatchFourConfigsTwoNodes(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// Register two nodes
	dispatcher.processNodeStatus("nodeA", "10.0.0.1", types.NodeStatus{})
	dispatcher.processNodeStatus("nodeB", "10.0.0.2", types.NodeStatus{})
	assert.Equal(t, 2, len(dispatcher.store.nodes))

	dispatcher.Schedule([]integration.Config{
		generateIntegration("A"),
		generateIntegration("B"),
		generateIntegration("C"),
		generateIntegration("D"),
	})

	allConfigs, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Equal(t, 4, len(allConfigs))
	assert.Equal(t, []string{"A", "B", "C", "D"}, extractCheckNames(allConfigs))

	configsA, _, err := dispatcher.getClusterCheckConfigs("nodeA")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(configsA))

	configsB, _, err := dispatcher.getClusterCheckConfigs("nodeB")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(configsB))

	// Make sure all checks are on a node
	names := extractCheckNames(configsA)
	names = append(names, extractCheckNames(configsB)...)
	sort.Strings(names)
	assert.Equal(t, []string{"A", "B", "C", "D"}, names)

	requireNotLocked(t, dispatcher.store)
}

func TestDanglingConfig(t *testing.T) {
	mockConfig := configmock.New(t)
	mockConfig.SetWithoutSource("cluster_checks.unscheduled_check_threshold", 1)
	mockConfig.SetWithoutSource("cluster_checks.node_expiration_timeout", 1)
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	config := integration.Config{
		Name:         "cluster-check",
		ClusterCheck: true,
	}

	assert.False(t, dispatcher.shouldDispatchDangling())

	// No node is available, config will be dispatched to the dummy "" node
	dispatcher.Schedule([]integration.Config{config})
	assert.Equal(t, 0, len(dispatcher.store.digestToNode))
	assert.Equal(t, 1, len(dispatcher.store.danglingConfigs))

	// shouldDispatchDangling is still false because no node is available
	assert.False(t, dispatcher.shouldDispatchDangling())

	// force config to dangle long enough to be classified as unscheduled check
	assert.False(t, dispatcher.store.danglingConfigs[config.Digest()].unscheduledCheck)
	require.Eventually(t, func() bool {
		dispatcher.scanUnscheduledChecks()
		return dispatcher.store.danglingConfigs[config.Digest()].unscheduledCheck
	}, 2*time.Second, 250*time.Millisecond)

	// register a node, shouldDispatchDangling will become true
	dispatcher.processNodeStatus("nodeA", "10.0.0.1", types.NodeStatus{})
	assert.True(t, dispatcher.shouldDispatchDangling())

	// get the danglings and make sure they are removed from the store
	configs := dispatcher.retrieveDangling()
	dispatcher.deleteDangling([]string{config.Digest()})
	assert.Len(t, configs, 1)
	assert.Equal(t, 0, len(dispatcher.store.danglingConfigs))
}

func TestUnscheduleDanglingConfig(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	testDispatcher := newDispatcher(fakeTagger)

	testConfig := integration.Config{
		Name:         "cluster-check-example",
		ClusterCheck: true,
		Instances: []integration.Data{
			// Define 2 to test that all of them are deleted and not just 1.
			integration.Data("tags: [\"t1:v1\"]"),
			integration.Data("tags: [\"t2:v2\"]"),
		},
	}

	// False because because no node is available
	assert.False(t, testDispatcher.shouldDispatchDangling())

	// No nodes created, so it will not get assigned
	testDispatcher.Schedule([]integration.Config{testConfig})

	testDispatcher.Unschedule([]integration.Config{testConfig})

	configs, err := testDispatcher.getAllConfigs()
	require.NoError(t, err)
	assert.Empty(t, configs)

	// Also check that internal structures not used by getAllConfigs() are cleaned up
	assert.Empty(t, testDispatcher.store.danglingConfigs)
	assert.Empty(t, testDispatcher.store.idToDigest)
}

func TestReset(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)
	config := generateIntegration("cluster-check")

	// Register to node1
	dispatcher.addConfig(config, "node1")
	configs1, _, err := dispatcher.getClusterCheckConfigs("node1")
	assert.NoError(t, err)
	assert.Len(t, configs1, 1)
	assert.Contains(t, configs1, config)

	// Reset
	dispatcher.reset()
	stored, err := dispatcher.getAllConfigs()
	assert.NoError(t, err)
	assert.Len(t, stored, 0)
	_, _, err = dispatcher.getClusterCheckConfigs("node1")
	assert.EqualError(t, err, "node node1 is unknown")

	requireNotLocked(t, dispatcher.store)
}

func TestPatchConfiguration(t *testing.T) {
	env.SetFeatures(t, env.Kubernetes)

	checkConfig := integration.Config{
		Name:          "test",
		ADIdentifiers: []string{"redis"},
		ClusterCheck:  true,
		InitConfig:    integration.Data("{foo}"),
		Instances:     []integration.Data{integration.Data("tags: [\"foo:bar\", \"bar:foo\"]")},
		LogsConfig:    integration.Data("[{\"service\":\"any_service\",\"source\":\"any_source\"}]"),
	}
	initialDigest := checkConfig.Digest()

	fakeTagger := taggerfxmock.SetupFakeTagger(t)

	mockConfig := configmock.New(t)
	mockConfig.SetWithoutSource("cluster_name", "testing")
	clustername.ResetClusterName()

	dispatcher := newDispatcher(fakeTagger)
	out, err := dispatcher.patchConfiguration(checkConfig)
	assert.NoError(t, err)

	// Make sure we modify the copy but not the original
	assert.Equal(t, initialDigest, checkConfig.Digest())
	assert.NotEqual(t, initialDigest, out.Digest())

	assert.False(t, out.ClusterCheck)
	assert.Len(t, out.ADIdentifiers, 0)
	require.Len(t, out.Instances, 1)

	rawConfig := integration.RawMap{}
	err = yaml.Unmarshal(out.Instances[0], &rawConfig)
	assert.NoError(t, err)
	assert.Contains(t, rawConfig["tags"], "foo:bar")
	assert.Contains(t, rawConfig["tags"], "cluster_name:testing")
	assert.Contains(t, rawConfig["tags"], "kube_cluster_name:testing")
	assert.Equal(t, true, rawConfig["empty_default_hostname"])
}

func TestPatchEndpointsConfiguration(t *testing.T) {
	env.SetFeatures(t, env.Kubernetes)

	checkConfig := integration.Config{
		Name:          "test",
		ADIdentifiers: []string{"redis"},
		ClusterCheck:  true,
		InitConfig:    integration.Data("{foo}"),
		Instances:     []integration.Data{integration.Data("tags: [\"foo:bar\", \"bar:foo\"]")},
		LogsConfig:    integration.Data("[{\"service\":\"any_service\",\"source\":\"any_source\"}]"),
	}

	fakeTagger := taggerfxmock.SetupFakeTagger(t)

	mockConfig := configmock.New(t)
	mockConfig.SetWithoutSource("cluster_name", "testing")
	clustername.ResetClusterName()

	dispatcher := newDispatcher(fakeTagger)
	out, err := dispatcher.patchEndpointsConfiguration(checkConfig)
	assert.NoError(t, err)

	assert.False(t, out.ClusterCheck)
	assert.Len(t, out.ADIdentifiers, 1)
	require.Len(t, out.Instances, 1)

	rawConfig := integration.RawMap{}
	err = yaml.Unmarshal(out.Instances[0], &rawConfig)
	assert.NoError(t, err)
	assert.Contains(t, rawConfig["tags"], "foo:bar")
	assert.Contains(t, rawConfig["tags"], "cluster_name:testing")
	assert.Contains(t, rawConfig["tags"], "kube_cluster_name:testing")
	assert.Equal(t, nil, rawConfig["empty_default_hostname"])
}

func TestExtraTags(t *testing.T) {
	env.SetFeatures(t, env.Kubernetes)

	for _, tc := range []struct {
		extraTagsConfig   []string
		clusterNameConfig string
		tagNameConfig     string
		expected          []string
	}{
		{nil, "testing", "cluster_name", []string{"cluster_name:testing", "kube_cluster_name:testing"}},
		{nil, "mycluster", "custom_name", []string{"custom_name:mycluster", "kube_cluster_name:mycluster"}},
		{nil, "", "cluster_name", []string{}},
		{nil, "testing", "", []string{"kube_cluster_name:testing"}},
		{[]string{"one", "two"}, "", "", []string{"one", "two"}},
		{[]string{"one", "two"}, "mycluster", "custom_name", []string{"one", "two", "custom_name:mycluster", "kube_cluster_name:mycluster"}},
	} {
		t.Run("", func(t *testing.T) {
			fakeTagger := taggerfxmock.SetupFakeTagger(t)
			mockConfig := configmock.New(t)
			fakeTagger.SetGlobalTags(tc.extraTagsConfig, []string{}, []string{}, []string{})
			mockConfig.SetWithoutSource("cluster_name", tc.clusterNameConfig)
			mockConfig.SetWithoutSource("cluster_checks.cluster_tag_name", tc.tagNameConfig)

			clustername.ResetClusterName()
			dispatcher := newDispatcher(fakeTagger)
			assert.EqualValues(t, tc.expected, dispatcher.extraTags)
		})
	}
}

func TestGetAllEndpointsCheckConfigs(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	dispatcher := newDispatcher(fakeTagger)

	// Register configs to different nodes
	dispatcher.addEndpointConfig(generateEndpointsIntegration("endpoints-check1", "node1", false), "node1")
	dispatcher.addEndpointConfig(generateEndpointsIntegration("endpoints-check2", "node1", false), "node1")
	dispatcher.addEndpointConfig(generateEndpointsIntegration("endpoints-check3", "node2", false), "node2")

	// Get state
	configs, err := dispatcher.getAllEndpointsCheckConfigs()

	assert.NoError(t, err)
	assert.Len(t, configs, 3)
	assert.Contains(t, configs, generateEndpointsIntegration("endpoints-check1", "node1", false))
	assert.Contains(t, configs, generateEndpointsIntegration("endpoints-check2", "node1", false))
	assert.Contains(t, configs, generateEndpointsIntegration("endpoints-check3", "node2", false))

	requireNotLocked(t, dispatcher.store)
}

// dummyClcRunnerClient mocks the clcRunnersClient
var dummyClcRunnerClient dummyClientStruct

type dummyClientStruct struct{}

//nolint:revive // TODO(CINT) Fix revive linter
func (d *dummyClientStruct) GetVersion(IP string) (version.Version, error) {
	return version.Version{}, nil
}

func (d *dummyClientStruct) GetRunnerStats(IP string) (types.CLCRunnersStats, error) {
	stats := map[string]types.CLCRunnersStats{
		"10.0.0.1": {
			"http_check:My Nginx Service:b0041608e66d20ba": {
				AverageExecutionTime: 241,
				MetricSamples:        3,
			},
		},
		"10.0.0.2": {
			"kube_apiserver_metrics:c5d2d20ccb4bb880": {
				AverageExecutionTime: 858,
				MetricSamples:        1562,
			},
		},
	}
	return stats[IP], nil
}

func (d *dummyClientStruct) GetRunnerWorkers(IP string) (types.Workers, error) {
	workers := map[string]types.Workers{
		"10.0.0.1": {
			Count: 1,
			Instances: map[string]types.WorkerInfo{
				"worker_1": {
					Utilization: 0.1,
				},
			},
		},
		"10.0.0.2": {
			Count: 2,
			Instances: map[string]types.WorkerInfo{
				"worker_1": {
					Utilization: 0.1,
				},
				"worker_2": {
					Utilization: 0.2,
				},
			},
		},
	}

	return workers[IP], nil
}

func TestUpdateRunnersStats(t *testing.T) {
	fakeTagger := taggerfxmock.SetupFakeTagger(t)
	mockConfig := configmock.New(t)
	mockConfig.SetWithoutSource("cluster_checks.rebalance_with_utilization", true)

	dispatcher := newDispatcher(fakeTagger)
	status := types.NodeStatus{LastChange: 10}
	dispatcher.store.active = true

	dispatcher.clcRunnersClient = &dummyClcRunnerClient

	stats1 := types.CLCRunnersStats{
		"http_check:My Nginx Service:b0041608e66d20ba": {
			AverageExecutionTime: 241,
			MetricSamples:        3,
		},
	}

	stats2 := types.CLCRunnersStats{
		"kube_apiserver_metrics:c5d2d20ccb4bb880": {
			AverageExecutionTime: 858,
			MetricSamples:        1562,
		},
	}

	_ = dispatcher.processNodeStatus("node1", "10.0.0.1", status)
	_ = dispatcher.processNodeStatus("node2", "10.0.0.2", status)

	node1, found := dispatcher.store.getNodeStore("node1")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.1", node1.clientIP)
	assert.EqualValues(t, types.CLCRunnersStats{}, node1.clcRunnerStats)
	assert.Zero(t, node1.workers)

	node2, found := dispatcher.store.getNodeStore("node2")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.2", node2.clientIP)
	assert.EqualValues(t, types.CLCRunnersStats{}, node2.clcRunnerStats)
	assert.Zero(t, node2.workers)

	dispatcher.updateRunnersStats()

	node1, found = dispatcher.store.getNodeStore("node1")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.1", node1.clientIP)
	assert.EqualValues(t, stats1, node1.clcRunnerStats)
	assert.Equal(t, 1, node1.workers)

	node2, found = dispatcher.store.getNodeStore("node2")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.2", node2.clientIP)
	assert.EqualValues(t, stats2, node2.clcRunnerStats)
	assert.Equal(t, 2, node2.workers)

	// Switch node1 and node2 stats
	_ = dispatcher.processNodeStatus("node2", "10.0.0.1", status)
	_ = dispatcher.processNodeStatus("node1", "10.0.0.2", status)

	dispatcher.updateRunnersStats()

	node1, found = dispatcher.store.getNodeStore("node1")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.2", node1.clientIP)
	assert.EqualValues(t, stats2, node1.clcRunnerStats)

	node2, found = dispatcher.store.getNodeStore("node2")
	assert.True(t, found)
	assert.EqualValues(t, "10.0.0.1", node2.clientIP)
	assert.EqualValues(t, stats1, node2.clcRunnerStats)

	requireNotLocked(t, dispatcher.store)
}
