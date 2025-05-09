// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package k8s

import (
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// NewCRDCollectorVersions builds the group of collector versions.
func NewCRDCollectorVersions() collectors.CollectorVersions {
	return collectors.NewCollectorVersions(
		NewCRDCollector(),
	)
}

// CRDCollector is a collector for Kubernetes CRDs.
type CRDCollector struct {
	informer  informers.GenericInformer
	lister    cache.GenericLister
	metadata  *collectors.CollectorMetadata
	processor *processors.Processor
}

// NewCRDCollector creates a new collector for the Kubernetes CRD
// resource.
func NewCRDCollector() *CRDCollector {
	return &CRDCollector{
		metadata: &collectors.CollectorMetadata{
			IsDefaultVersion:                     true,
			IsStable:                             true,
			IsManifestProducer:                   true,
			IsMetadataProducer:                   false,
			SupportsManifestBuffering:            false,
			Name:                                 crdName,
			Kind:                                 kubernetes.CustomResourceDefinitionKind,
			NodeType:                             orchestrator.K8sCRD,
			Version:                              crdVersion,
			SupportsTerminatedResourceCollection: true,
		},
		processor: processors.NewProcessor(new(k8sProcessors.CRDHandlers)),
	}
}

// Informer returns the shared informer.
func (c *CRDCollector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

// Init is used to initialize the collector.
func (c *CRDCollector) Init(rcfg *collectors.CollectorRunConfig) {
	groupVersionResource := v1.SchemeGroupVersion.WithResource("customresourcedefinitions")
	var err error
	c.informer, err = rcfg.OrchestratorInformerFactory.CRDInformerFactory.ForResource(groupVersionResource)
	if err != nil {
		log.Errorc(err.Error(), orchestrator.ExtraLogContext...)
	}
	c.lister = c.informer.Lister() // return that Lister
}

// Metadata is used to access information about the collector.
func (c *CRDCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *CRDCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	list, err := c.lister.List(labels.Everything())
	if err != nil {
		return nil, collectors.NewListingError(err)
	}

	return c.Process(rcfg, list)
}

// Process is used to process the list of resources and return the result.
func (c *CRDCollector) Process(rcfg *collectors.CollectorRunConfig, list interface{}) (*collectors.CollectorRunResult, error) {
	ctx := collectors.NewK8sProcessorContext(rcfg, c.metadata)

	processResult, listed, processed := c.processor.Process(ctx, list)

	if processed == -1 {
		return nil, collectors.ErrProcessingPanic
	}

	result := &collectors.CollectorRunResult{
		Result:             processResult,
		ResourcesListed:    listed,
		ResourcesProcessed: processed,
	}

	return result, nil
}
