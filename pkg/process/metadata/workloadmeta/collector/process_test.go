// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/DataDog/datadog-agent/comp/core"
	compcfg "github.com/DataDog/datadog-agent/comp/core/config"
	ipcmock "github.com/DataDog/datadog-agent/comp/core/ipc/mock"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafxmock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx-mock"
	workloadmetamock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/mock"
	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	workloadmetaExtractor "github.com/DataDog/datadog-agent/pkg/process/metadata/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/DataDog/datadog-agent/pkg/process/procutil/mocks"
	proccontainersmock "github.com/DataDog/datadog-agent/pkg/process/util/containers/mocks"
	pbgo "github.com/DataDog/datadog-agent/pkg/proto/pbgo/process"

	"github.com/DataDog/datadog-agent/pkg/trace/testutil"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

const testCid = "containersAreAwesome"

type collectorTest struct {
	probe        *mocks.Probe
	clock        *clock.Mock
	collector    *Collector
	store        workloadmetamock.Mock
	stream       pbgo.ProcessEntityStream_StreamEntitiesClient
	mockProvider *proccontainersmock.MockContainerProvider
}

func acquireStream(t *testing.T, port int, tlsConfig *tls.Config) pbgo.ProcessEntityStream_StreamEntitiesClient {
	t.Helper()

	cc, err := grpc.Dial(fmt.Sprintf("localhost:%v", port), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))) //nolint:staticcheck // TODO (ASC) fix grpc.Dial is deprecated
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cc.Close()
	})

	stream, err := pbgo.NewProcessEntityStreamClient(cc).StreamEntities(context.Background(), &pbgo.ProcessStreamEntitiesRequest{})
	require.NoError(t, err)

	return stream
}

func setFlavor(t *testing.T, newFlavor string) {
	t.Helper()

	oldFlavor := flavor.GetFlavor()
	flavor.SetFlavor(newFlavor)
	t.Cleanup(func() { flavor.SetFlavor(oldFlavor) })
}

func setUpCollectorTest(t *testing.T) *collectorTest {
	t.Helper()

	setFlavor(t, flavor.ProcessAgent)

	port, err := testutil.FindTCPPort()
	require.NoError(t, err)

	overrides := map[string]interface{}{
		"process_config.language_detection.grpc_port":              port,
		"workloadmeta.remote_process_collector.enabled":            true,
		"workloadmeta.local_process_collector.collection_interval": 15 * time.Second,
	}

	ipcMock := ipcmock.New(t)

	store := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		fx.Replace(compcfg.MockParams{Overrides: overrides}),
		fx.Supply(context.Background()),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))

	// pass actual config component
	wlmExtractor := workloadmetaExtractor.NewWorkloadMetaExtractor(store.GetConfig())
	grpcServer := workloadmetaExtractor.NewGRPCServer(store.GetConfig(), wlmExtractor, ipcMock.GetTLSServerConfig())

	mockProcessData, probe := checks.NewProcessDataWithMockProbe(t)
	mockProcessData.Register(wlmExtractor)

	mockClock := clock.NewMock()

	mockCtrl := gomock.NewController(t)
	mockProvider := proccontainersmock.NewMockContainerProvider(mockCtrl)

	c := &Collector{
		ddConfig:          store.GetConfig(),
		processData:       mockProcessData,
		wlmExtractor:      wlmExtractor,
		grpcServer:        grpcServer,
		pidToCid:          make(map[int]string),
		collectionClock:   mockClock,
		containerProvider: mockProvider,
	}
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, c.Start(ctx, store))
	t.Cleanup(cancel)

	return &collectorTest{
		collector:    c,
		probe:        probe,
		clock:        mockClock,
		store:        store,
		stream:       acquireStream(t, port, ipcMock.GetTLSClientConfig()),
		mockProvider: mockProvider,
	}
}

func (c *collectorTest) setupProcs() {
	c.probe.On("ProcessesByPID", mock.Anything, mock.Anything).Return(map[int32]*procutil.Process{
		1: {
			Pid:     1,
			Cmdline: []string{"some-awesome-game", "--with-rgb", "--give-me-more-fps"},
			Stats:   &procutil.Stats{CreateTime: 1},
		},
	}, nil).Maybe()
}

// Tick sets up the collector to collect processes by advancing the clock
func (c *collectorTest) tick() {
	c.clock.Add(c.store.GetConfig().GetDuration("workloadmeta.local_process_collector.collection_interval"))
}

func TestProcessCollector(t *testing.T) {
	c := setUpCollectorTest(t)
	c.setupProcs()

	// Fast-forward through sync message
	resp, err := c.stream.Recv()
	require.NoError(t, err)
	fmt.Printf("1: %v\n", resp.String())

	// Testing container id enrichment
	c.mockProvider.EXPECT().GetPidToCid(2 * time.Second).Return(map[int]string{1: testCid}).MinTimes(1)

	c.tick()
	resp, err = c.stream.Recv()
	assert.NoError(t, err)
	fmt.Printf("2: %v\n", resp.String())

	require.Len(t, resp.SetEvents, 1)
	evt := resp.SetEvents[0]
	assert.EqualValues(t, 1, evt.Pid)
	assert.EqualValues(t, 1, evt.CreationTime)
	assert.Equal(t, testCid, evt.ContainerID)
}

// Assert that the collector is only enabled if the process check is disabled and
// the remote process collector is enabled.
func TestEnabled(t *testing.T) {
	type testCase struct {
		name                                                                           string
		processCollectionEnabled, remoteProcessCollectorEnabled, runInCoreAgentEnabled bool
		expectEnabled                                                                  bool
		flavor                                                                         string
	}

	testCases := []testCase{
		{
			name:                          "process check enabled",
			processCollectionEnabled:      true,
			remoteProcessCollectorEnabled: false,
			runInCoreAgentEnabled:         false,
			flavor:                        flavor.ProcessAgent,
			expectEnabled:                 false,
		},
		{
			name:                          "remote collector disabled",
			processCollectionEnabled:      false,
			remoteProcessCollectorEnabled: false,
			runInCoreAgentEnabled:         false,
			flavor:                        flavor.ProcessAgent,
			expectEnabled:                 false,
		},
		{
			name:                          "collector enabled",
			processCollectionEnabled:      false,
			remoteProcessCollectorEnabled: true,
			runInCoreAgentEnabled:         false,
			flavor:                        flavor.ProcessAgent,
			expectEnabled:                 true,
		},
		{
			name:                          "collector enabled but in core agent",
			processCollectionEnabled:      false,
			remoteProcessCollectorEnabled: true,
			runInCoreAgentEnabled:         true,
			flavor:                        flavor.ProcessAgent,
			expectEnabled:                 false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setFlavor(t, tc.flavor)

			cfg := configmock.New(t)
			cfg.SetWithoutSource("process_config.process_collection.enabled", tc.processCollectionEnabled)
			cfg.SetWithoutSource("language_detection.enabled", tc.remoteProcessCollectorEnabled)
			cfg.SetWithoutSource("process_config.run_in_core_agent.enabled", tc.runInCoreAgentEnabled)

			assert.Equal(t, tc.expectEnabled, Enabled(cfg))
		})
	}
}
