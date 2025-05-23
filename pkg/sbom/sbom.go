// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package sbom holds sbom related files
package sbom

import (
	"time"

	"github.com/DataDog/datadog-agent/comp/core/config"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/sbom/types"

	cyclonedxgo "github.com/CycloneDX/cyclonedx-go"
)

const (
	ScanFilesystemType = "filesystem" // ScanFilesystemType defines the type for file-system scan
	ScanDaemonType     = "daemon"     // ScanDaemonType defines the type for daemon scan
)

// Report defines the report interface
type Report interface {
	ToCycloneDX() (*cyclonedxgo.BOM, error)
	ID() string
}

// ScanOptionsFromConfigForContainers loads the scanning options from the configuration
func ScanOptionsFromConfigForContainers(cfg config.Component) ScanOptions {
	return ScanOptions{
		CheckDiskUsage:   cfg.GetBool("sbom.container_image.check_disk_usage"),
		MinAvailableDisk: uint64(cfg.GetSizeInBytes("sbom.container_image.min_available_disk")),
		Timeout:          time.Duration(cfg.GetInt("sbom.container_image.scan_timeout")) * time.Second,
		WaitAfter:        time.Duration(cfg.GetInt("sbom.container_image.scan_interval")) * time.Second,
		Analyzers:        cfg.GetStringSlice("sbom.container_image.analyzers"),
		UseMount:         cfg.GetBool("sbom.container_image.use_mount"),
		OverlayFsScan:    cfg.GetBool("sbom.container_image.overlayfs_direct_scan"),
	}
}

// ScanOptionsFromConfigForHosts loads the scanning options from the configuration
func ScanOptionsFromConfigForHosts(cfg config.Component) ScanOptions {
	return ScanOptions{
		Analyzers: cfg.GetStringSlice("sbom.host.analyzers"),
	}
}

// ScanRequest defines the scan request interface
type ScanRequest = types.ScanRequest

// ScanOptions defines the scan options
type ScanOptions = types.ScanOptions

// ScanResult defines the scan result
type ScanResult struct {
	Error     error
	Report    Report
	CreatedAt time.Time
	Duration  time.Duration
	ImgMeta   *workloadmeta.ContainerImageMetadata
	RequestID string
}
