// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build docker

package docker

import (
	"context"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"

	"github.com/DataDog/datadog-agent/pkg/util/containers"
)

// MockClient is a mock implementation of docker.Client interface
// Should probably be generated at some point
type MockClient struct {
	FakeRawClient                   *client.Client
	FakeContainerList               []container.Summary
	FakeImageNameMapping            map[string]string
	FakeImages                      []image.Summary
	FakeStorageStats                []*StorageStats
	FakeAttachedVolumes             int
	FakeDandlingVolumes             int
	FakeContainerEvents             []*ContainerEvent
	FakeLastContainerEventTimestamp time.Time
	FakeError                       error
}

// RawClient is a mock method
func (d *MockClient) RawClient() *client.Client {
	return d.FakeRawClient
}

// RawContainerList is a mock method
func (d *MockClient) RawContainerList(context.Context, container.ListOptions) ([]container.Summary, error) {
	return d.FakeContainerList, d.FakeError
}

// ResolveImageName is a mock method
//
//nolint:revive // TODO(CINT) Fix revive linter
func (d *MockClient) ResolveImageName(ctx context.Context, image string) (string, error) {
	return d.FakeImageNameMapping[image], d.FakeError
}

// Images is a mock method
func (d *MockClient) Images(context.Context, bool) ([]image.Summary, error) {
	return d.FakeImages, d.FakeError
}

// GetPreferredImageName is a mock method
//
//nolint:revive // TODO(CINT) Fix revive linter
func (d *MockClient) GetPreferredImageName(imageID string, repoTags []string, repoDigests []string) string {
	return d.FakeImageNameMapping[imageID]
}

// GetStorageStats is a mock method
//
//nolint:revive // TODO(CINT) Fix revive linter
func (d *MockClient) GetStorageStats(ctx context.Context) ([]*StorageStats, error) {
	return d.FakeStorageStats, d.FakeError
}

// CountVolumes is a mock method
//
//nolint:revive // TODO(CINT) Fix revive linter
func (d *MockClient) CountVolumes(ctx context.Context) (int, int, error) {
	return d.FakeAttachedVolumes, d.FakeDandlingVolumes, d.FakeError
}

// LatestContainerEvents is a mock method
//
//nolint:revive // TODO(CINT) Fix revive linter
func (d *MockClient) LatestContainerEvents(ctx context.Context, since time.Time, filter *containers.Filter) ([]*ContainerEvent, time.Time, error) {
	return d.FakeContainerEvents, d.FakeLastContainerEventTimestamp, d.FakeError
}
