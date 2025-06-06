// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package remote implements a generic workloadmeta Collector that receives
// events from a remote workloadmeta server.
package remote

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/telemetry"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	grpcutil "github.com/DataDog/datadog-agent/pkg/util/grpc"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	noTimeout         = 0 * time.Minute
	streamRecvTimeout = 10 * time.Minute
)

var errWorkloadmetaStreamNotStarted = errors.New("workloadmeta stream not started")

// GrpcClient interface that represents a gRPC client for the remote workloadmeta.
type GrpcClient interface {
	// StreamEntities establishes the stream between the client and the remote gRPC server.
	StreamEntities(ctx context.Context) (Stream, error)
}

// Stream is an interface that represents a gRPC stream.
type Stream interface {
	// Recv returns a response of the gRPC server
	Recv() (interface{}, error)
}

// StreamHandler is an interface that defines a gRPC stream handler.
type StreamHandler interface {
	// Port returns the targeted port
	Port() int
	// IsEnabled returns if the feature is enabled
	IsEnabled() bool
	// NewClient returns a client to connect to a remote gRPC server.
	NewClient(cc grpc.ClientConnInterface) GrpcClient
	// HandleResponse handles a response from the remote gRPC server.
	HandleResponse(store workloadmeta.Component, response interface{}) ([]workloadmeta.CollectorEvent, error)
	// HandleResync is called on resynchronization.
	HandleResync(store workloadmeta.Component, events []workloadmeta.CollectorEvent)
}

// GenericCollector is a generic remote workloadmeta collector with resync mechanisms.
type GenericCollector struct {
	CollectorID   string
	Catalog       workloadmeta.AgentType
	StreamHandler StreamHandler

	store        workloadmeta.Component
	resyncNeeded bool

	client GrpcClient
	stream Stream

	streamCtx    context.Context
	streamCancel context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc

	IPC ipc.Component
}

// Start starts the generic collector
func (c *GenericCollector) Start(ctx context.Context, store workloadmeta.Component) error {
	if !c.StreamHandler.IsEnabled() {
		return fmt.Errorf("collector %s is not enabled", c.CollectorID)
	}

	c.store = store

	c.ctx, c.cancel = context.WithCancel(ctx)

	opts := []grpc.DialOption{grpc.WithContextDialer(func(_ context.Context, url string) (net.Conn, error) {
		return net.Dial("tcp", url)
	})}

	creds := credentials.NewTLS(c.IPC.GetTLSClientConfig())
	opts = append(opts, grpc.WithTransportCredentials(creds))

	conn, err := grpc.DialContext( //nolint:staticcheck // TODO (ASC) fix grpc.DialContext is deprecated
		c.ctx,
		fmt.Sprintf(":%v", c.StreamHandler.Port()),
		opts...,
	)
	if err != nil {
		return err
	}

	c.client = c.StreamHandler.NewClient(conn)

	log.Info("remote workloadmeta initialized successfully")
	go c.Run()

	return nil
}

// Pull does nothing in workloadmeta collectors.
func (c *GenericCollector) Pull(context.Context) error {
	return nil
}

func (c *GenericCollector) startWorkloadmetaStream(maxElapsed time.Duration) error {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 500 * time.Millisecond
	expBackoff.MaxInterval = 5 * time.Minute
	expBackoff.MaxElapsedTime = maxElapsed

	return backoff.Retry(func() error {
		select {
		case <-c.ctx.Done():
			return &backoff.PermanentError{Err: errWorkloadmetaStreamNotStarted}
		default:
		}

		var err error

		c.streamCtx, c.streamCancel = context.WithCancel(
			metadata.NewOutgoingContext(
				c.ctx,
				metadata.MD{
					"authorization": []string{
						fmt.Sprintf("Bearer %s", c.IPC.GetAuthToken()), // TODO IPC: Remove this raw usage of the auth token
					},
				},
			),
		)

		c.stream, err = c.client.StreamEntities(c.streamCtx)
		if err != nil {
			log.Infof("unable to establish stream, will possibly retry: %s", err)
			return err
		}

		log.Info("workloadmeta stream established successfully")
		return nil
	}, expBackoff)
}

// Run will run the generic collector streaming loop
func (c *GenericCollector) Run() {
	recvWithoutTimeout := pkgconfigsetup.Datadog().GetBool("workloadmeta.remote.recv_without_timeout")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if c.stream == nil {
			if err := c.startWorkloadmetaStream(noTimeout); err != nil {
				log.Warnf("error received trying to start stream: %s", err)
				continue
			}
		}

		var (
			response interface{}
			err      error
		)
		if recvWithoutTimeout {
			response, err = c.stream.Recv()
		} else {
			err = grpcutil.DoWithTimeout(func() error {
				var err error
				response, err = c.stream.Recv()
				return err
			}, streamRecvTimeout)
		}
		if err != nil {
			c.streamCancel()

			// when Recv() returns an error, the stream is aborted and the
			// contents of our store are considered out of sync. The stream must
			// be re-established. No events are notified to the store until the
			// connection is re-established.
			c.stream = nil
			c.resyncNeeded = true

			if err != io.EOF {
				telemetry.RemoteClientErrors.Inc(c.CollectorID)
				log.Warnf("error received from remote workloadmeta: %s", err)
			}

			continue
		}

		collectorEvents, err := c.StreamHandler.HandleResponse(c.store, response)
		if err != nil {
			log.Warnf("error processing event received from remote workloadmeta: %s", err)
			continue
		}

		if c.resyncNeeded {
			c.StreamHandler.HandleResync(c.store, collectorEvents)
			c.resyncNeeded = false
		} else {
			c.store.Notify(collectorEvents)
		}
	}
}

// GetID gets the identifier for the generic collector
func (c *GenericCollector) GetID() string {
	return c.CollectorID
}

// GetTargetCatalog gets the catalog this collector should target
func (c *GenericCollector) GetTargetCatalog() workloadmeta.AgentType {
	return c.Catalog
}
