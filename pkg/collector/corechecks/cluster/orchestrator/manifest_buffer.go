// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator

package orchestrator

import (
	"expvar"
	"sync"
	"time"

	"go.uber.org/atomic"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/common"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	pkgorchestratormodel "github.com/DataDog/datadog-agent/pkg/orchestrator/model"
	"github.com/DataDog/datadog-agent/pkg/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var (
	globalMu                sync.Mutex
	bufferExpVars           = expvar.NewMap("orchestrator-manifest-buffer")
	manifestFlushed         = &expvar.Int{}
	bufferFlushedTotal      = &expvar.Int{}
	tlmBufferedManifest     = telemetry.NewCounter("orchestrator", "manifest_buffered", []string{"orchestrator", "resource"}, "Number of manifest buffered")
	tlmManifestFlushed      = telemetry.NewCounter("orchestrator", "manifest_flushed", nil, "Number of manifest flushed")
	tlmManifestFlushedTotal = telemetry.NewCounter("orchestrator", "manifest_flushed_total", nil, "Number of times the buffer is flushed")
)

func init() {
	bufferExpVars.Set("ManifestsFlushedLastTime", manifestFlushed)
	bufferExpVars.Set("BufferFlushed", bufferFlushedTotal)
}

// ManifestBufferConfig contains information about buffering manifests.
type ManifestBufferConfig struct {
	KubeClusterName             string
	ClusterID                   string
	MaxPerMessage               int
	MaxWeightPerMessageBytes    int
	MsgGroupRef                 *atomic.Int32
	BufferedManifestEnabled     bool
	MaxBufferedManifests        int
	ManifestBufferFlushInterval time.Duration
	ExtraTags                   []string
}

// ManifestBuffer is a buffer of manifest sent from all collectors
// It has a slice bufferedManifests used to buffer manifest and stop channel
// ManifestBuffer is started as a dedicated thread each time CollectorBundle runs a check
// and gets stopped after the check is done.
type ManifestBuffer struct {
	Cfg               *ManifestBufferConfig
	ManifestChan      chan interface{}
	bufferedManifests []interface{}
	stopCh            chan struct{}
	wg                sync.WaitGroup
}

// NewManifestBuffer returns a new ManifestBuffer
func NewManifestBuffer(chk *OrchestratorCheck) *ManifestBuffer {
	manifestBuffer := &ManifestBuffer{
		Cfg: &ManifestBufferConfig{
			ClusterID:                   chk.clusterID,
			KubeClusterName:             chk.orchestratorConfig.KubeClusterName,
			MsgGroupRef:                 chk.groupID,
			MaxPerMessage:               chk.orchestratorConfig.MaxPerMessage,
			MaxWeightPerMessageBytes:    chk.orchestratorConfig.MaxWeightPerMessageBytes,
			BufferedManifestEnabled:     chk.orchestratorConfig.BufferedManifestEnabled,
			MaxBufferedManifests:        chk.orchestratorConfig.MaxPerMessage,
			ManifestBufferFlushInterval: chk.orchestratorConfig.ManifestBufferFlushInterval,
			ExtraTags:                   chk.orchestratorConfig.ExtraTags,
		},
		ManifestChan: make(chan interface{}),
		stopCh:       make(chan struct{}),
	}
	manifestBuffer.bufferedManifests = make([]interface{}, 0, manifestBuffer.Cfg.MaxBufferedManifests)

	return manifestBuffer
}

// flushManifest flushes manifests by chunking them first then sending them to the sender
func (cb *ManifestBuffer) flushManifest(sender sender.Sender) {
	manifests := cb.bufferedManifests
	ctx := &processors.K8sProcessorContext{
		BaseProcessorContext: processors.BaseProcessorContext{
			MsgGroupID: cb.Cfg.MsgGroupRef.Inc(),
			Cfg: &config.OrchestratorConfig{
				KubeClusterName:          cb.Cfg.KubeClusterName,
				MaxPerMessage:            cb.Cfg.MaxPerMessage,
				MaxWeightPerMessageBytes: cb.Cfg.MaxWeightPerMessageBytes,
				ExtraTags:                cb.Cfg.ExtraTags,
			},
			ClusterID: cb.Cfg.ClusterID,
		},
	}
	manifestMessages := processors.ChunkManifest(ctx, common.BaseHandlers{}.BuildManifestMessageBody, manifests)
	sender.OrchestratorManifest(manifestMessages, cb.Cfg.ClusterID)
	setManifestStats(manifests)
	cb.bufferedManifests = cb.bufferedManifests[:0]
}

// appendManifest appends manifest into the buffer
// If buffer is full, it will flush the buffer first then append the manifest
func (cb *ManifestBuffer) appendManifest(m interface{}, sender sender.Sender) {
	if len(cb.bufferedManifests) >= cb.Cfg.MaxBufferedManifests {
		cb.flushManifest(sender)
	}

	cb.bufferedManifests = append(cb.bufferedManifests, m)
}

// Start is to start a thread to buffer manifest and send them
// It flushes manifests every defaultFlushManifestTime
func (cb *ManifestBuffer) Start(sender sender.Sender) {
	cb.wg.Add(1)

	go func() {
		ticker := time.NewTicker(cb.Cfg.ManifestBufferFlushInterval)
		defer func() {
			ticker.Stop()
			cb.wg.Done()
		}()
	loop:
		for {
			select {
			case msg, ok := <-cb.ManifestChan:
				if !ok {
					log.Warnc("Fail to read orchestrator manifest from channel", orchestrator.ExtraLogContext...)
					continue
				}
				cb.appendManifest(msg, sender)
			case <-ticker.C:
				cb.flushManifest(sender)
			case <-cb.stopCh:
				cb.flushManifest(sender)
				break loop
			}
		}
	}()
}

// Stop is to kill the thread collecting manifest
func (cb *ManifestBuffer) Stop() {
	cb.stopCh <- struct{}{}
	cb.wg.Wait()
}

// BufferManifestProcessResult is to add process result to the buffer
func BufferManifestProcessResult(messages []model.MessageBody, buffer *ManifestBuffer) {
	for _, message := range messages {
		m := message.(*model.CollectorManifest)
		for _, manifest := range m.Manifests {
			buffer.ManifestChan <- manifest
		}
	}
}

func setManifestStats(manifests []interface{}) {
	globalMu.Lock()
	defer globalMu.Unlock()

	// Number of manifests flushed
	manifestFlushed.Set(int64(len(manifests)))
	tlmManifestFlushed.Add(float64(len(manifests)))

	// Number of times the buffer is flushed
	bufferFlushedTotal.Add(1)
	tlmManifestFlushedTotal.Inc()
	// Number of manifests flushed per resource in total
	for _, m := range manifests {
		nodeType := pkgorchestratormodel.NodeType(m.(*model.Manifest).Type)
		nodeTypeStr := nodeType.String()

		// Get the existing expvar.Int for this node type, or create a new one if it doesn't exist
		var expvarInt *expvar.Int
		if v := bufferExpVars.Get(nodeTypeStr); v == nil {
			expvarInt = new(expvar.Int)
			bufferExpVars.Set(nodeTypeStr, expvarInt)
		} else {
			expvarInt = v.(*expvar.Int)
		}

		// Increment the counter
		expvarInt.Add(1)
		tlmBufferedManifest.Inc(nodeType.TelemetryTags()...)
	}
}
