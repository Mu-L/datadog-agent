// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package workloadmeta

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/DataDog/datadog-agent/comp/core"
	ipcmock "github.com/DataDog/datadog-agent/comp/core/ipc/mock"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafxmock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx-mock"
	workloadmetamock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/mock"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/proto"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/server"
	pbgo "github.com/DataDog/datadog-agent/pkg/proto/pbgo/core"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type serverSecure struct {
	pbgo.UnimplementedAgentSecureServer
	workloadmetaServer *server.Server
}

func (*serverSecure) TaggerStreamEntities(*pbgo.StreamTagsRequest, pbgo.AgentSecure_TaggerStreamEntitiesServer) error {
	return status.Errorf(codes.Unimplemented, "method TaggerStreamEntities not implemented")
}
func (*serverSecure) TaggerFetchEntity(context.Context, *pbgo.FetchEntityRequest) (*pbgo.FetchEntityResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TaggerFetchEntity not implemented")
}
func (*serverSecure) DogstatsdCaptureTrigger(context.Context, *pbgo.CaptureTriggerRequest) (*pbgo.CaptureTriggerResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdCaptureTrigger not implemented")
}
func (*serverSecure) DogstatsdSetTaggerState(context.Context, *pbgo.TaggerState) (*pbgo.TaggerStateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DogstatsdSetTaggerState not implemented")
}
func (*serverSecure) ClientGetConfigs(context.Context, *pbgo.ClientGetConfigsRequest) (*pbgo.ClientGetConfigsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClientGetConfigs not implemented")
}
func (*serverSecure) GetConfigState(context.Context, *emptypb.Empty) (*pbgo.GetStateConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfigState not implemented")
}
func (s *serverSecure) WorkloadmetaStreamEntities(in *pbgo.WorkloadmetaStreamRequest, out pbgo.AgentSecure_WorkloadmetaStreamEntitiesServer) error {
	return s.workloadmetaServer.StreamEntities(in, out)
}

func TestNewCollector(t *testing.T) {
	tests := []struct {
		name         string
		filter       *workloadmeta.Filter
		expectsError bool
	}{
		{
			name:         "nil filter",
			filter:       nil,
			expectsError: false,
		},
		{
			name: "filter with only supported kinds",
			filter: workloadmeta.NewFilterBuilder().
				AddKind(workloadmeta.KindContainer).
				AddKind(workloadmeta.KindKubernetesPod).
				Build(),
			expectsError: false,
		},
		{
			name: "filter with unsupported kinds",
			filter: workloadmeta.NewFilterBuilder().
				AddKind(workloadmeta.KindContainer).
				AddKind(workloadmeta.KindContainerImageMetadata /* No Supported */).
				Build(),
			expectsError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := dependencies{
				Params: Params{
					Filter: test.filter,
				},
			}

			_, err := NewCollector(deps)

			if test.expectsError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandleWorkloadmetaStreamResponse(t *testing.T) {
	protoWorkloadmetaEvent := &pbgo.WorkloadmetaEvent{
		Type: pbgo.WorkloadmetaEventType_EVENT_TYPE_SET,
		Container: &pbgo.Container{
			EntityId: &pbgo.WorkloadmetaEntityId{
				Kind: pbgo.WorkloadmetaKind_CONTAINER,
				Id:   "123",
			},
			EntityMeta: &pbgo.EntityMeta{
				Name:      "abc",
				Namespace: "default",
				Annotations: map[string]string{
					"an_annotation": "an_annotation_value",
				},
				Labels: map[string]string{
					"a_label": "a_label_value",
				},
			},
			EnvVars: map[string]string{
				"an_env": "an_env_val",
			},
			Hostname: "test_host",
			Image: &pbgo.ContainerImage{
				Id:        "123",
				RawName:   "datadog/agent:7",
				Name:      "datadog/agent",
				ShortName: "agent",
				Tag:       "7",
			},
			NetworkIps: map[string]string{
				"net1": "10.0.0.1",
				"net2": "192.168.0.1",
			},
			Pid: 0,
			Ports: []*pbgo.ContainerPort{
				{
					Port:     2000,
					Protocol: "tcp",
				},
			},
			Runtime: pbgo.Runtime_CONTAINERD,
			State: &pbgo.ContainerState{
				Running:    true,
				Status:     pbgo.ContainerStatus_CONTAINER_STATUS_RUNNING,
				Health:     pbgo.ContainerHealth_CONTAINER_HEALTH_HEALTHY,
				CreatedAt:  time.Time{}.Unix(),
				StartedAt:  time.Time{}.Unix(),
				FinishedAt: time.Time{}.Unix(),
				ExitCode:   0,
			},
			CollectorTags: []string{
				"tag1",
			},
		},
	}
	// workloadmeta client store
	mockClientStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		workloadmetafxmock.MockModule(workloadmeta.Params{AgentType: workloadmeta.Remote}),
	))

	expectedEvent, err := proto.WorkloadmetaEventFromProtoEvent(protoWorkloadmetaEvent)
	require.NoError(t, err)

	mockResponse := &pbgo.WorkloadmetaStreamResponse{
		Events: []*pbgo.WorkloadmetaEvent{protoWorkloadmetaEvent},
	}

	streamhandler := &streamHandler{}
	collectorEvents, err := streamhandler.HandleResponse(mockClientStore, mockResponse)

	require.NoError(t, err)
	assert.Len(t, collectorEvents, 1)
	assert.Equal(t, collectorEvents[0], workloadmeta.CollectorEvent{
		Type:   expectedEvent.Type,
		Entity: expectedEvent.Entity,
		Source: workloadmeta.SourceRemoteWorkloadmeta,
	})
}

func TestCollection(t *testing.T) {
	// Create ipc component for the client
	ipcComp := ipcmock.New(t)

	// workloadmeta server
	mockServerStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))
	server := &serverSecure{workloadmetaServer: server.NewServer(mockServerStore)}

	// gRPC server
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(ipcComp.GetTLSServerConfig())))
	pbgo.RegisterAgentSecureServer(grpcServer, server)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		err := grpcServer.Serve(lis)
		require.NoError(t, err)
	}()
	defer grpcServer.Stop()

	_, portStr, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	// gRPC client
	collector := &remote.GenericCollector{
		CollectorID: "generic-test-collector",
		Catalog:     workloadmeta.Remote,
		StreamHandler: &streamHandler{
			port: port,
		},
		IPC: ipcComp,
	}

	// workloadmeta client store
	mockClientStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		fx.Provide(
			fx.Annotate(func() workloadmeta.Collector {
				return collector
			},
				fx.ResultTags(`group:"workloadmeta"`)),
		),
		workloadmetafxmock.MockModule(workloadmeta.Params{AgentType: workloadmeta.Remote}),
	))

	time.Sleep(3 * time.Second)

	// Subscribe to the mockStore and wait for the initial event
	ch := mockClientStore.Subscribe("dummy", workloadmeta.NormalPriority, nil)

	// Start straming entites
	expectedContainer := &workloadmeta.Container{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindContainer,
			ID:   "ctr-id",
		},
		EntityMeta: workloadmeta.EntityMeta{
			Name: "ctr-name",
		},
		Image: workloadmeta.ContainerImage{
			Name: "ctr-image",
		},
		Runtime: workloadmeta.ContainerRuntimeDocker,
		State: workloadmeta.ContainerState{
			Running:    true,
			Status:     workloadmeta.ContainerStatusRunning,
			Health:     workloadmeta.ContainerHealthHealthy,
			CreatedAt:  time.Time{},
			StartedAt:  time.Time{},
			FinishedAt: time.Time{},
		},
		EnvVars: map[string]string{
			"DD_SERVICE":  "my-svc",
			"DD_ENV":      "prod",
			"DD_VERSION":  "v1",
			"NOT_ALLOWED": "not-allowed",
		},
	}

	collectorEvents := []workloadmeta.CollectorEvent{
		{
			Type:   workloadmeta.EventTypeSet,
			Source: workloadmeta.SourceAll,
			Entity: expectedContainer,
		},
	}

	mockServerStore.Notify(collectorEvents)

	// Number of events expected. We expect one per collectorEvent.

	numberOfEvents := len(collectorEvents)
	// Keep listening to workloadmeta until enough events are received. It is possible that the
	// first bundle does not hold any events. Thus, it is required to look at the number of events
	// in the bundle.
	for i := 0; i < numberOfEvents; {
		bundle := <-ch
		close(bundle.Ch)
		i += len(bundle.Events)
	}
	mockClientStore.Unsubscribe(ch)

	container, err := mockClientStore.GetContainer("ctr-id")
	require.NoError(t, err)
	assert.Equal(t, container, expectedContainer)
}
