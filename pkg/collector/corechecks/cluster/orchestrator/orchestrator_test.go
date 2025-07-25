// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator && test

package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/fx"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	crd "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	vpa "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/client/clientset/versioned/fake"
	cr "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	taggerfxmock "github.com/DataDog/datadog-agent/comp/core/tagger/fx-mock"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	workloadmetafxmock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/fx-mock"
	workloadmetamock "github.com/DataDog/datadog-agent/comp/core/workloadmeta/mock"
	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors/inventory"
	mockconfig "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
)

func newCollectorBundle(t *testing.T, chk *OrchestratorCheck) *CollectorBundle {
	cfg := mockconfig.New(t)
	mockStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))

	fakeTagger := taggerfxmock.SetupFakeTagger(t)

	bundle := &CollectorBundle{
		discoverCollectors: chk.orchestratorConfig.CollectorDiscoveryEnabled,
		check:              chk,
		inventory:          inventory.NewCollectorInventory(cfg, mockStore, fakeTagger),
		runCfg: &collectors.CollectorRunConfig{
			K8sCollectorRunConfig: collectors.K8sCollectorRunConfig{
				APIClient:                   chk.apiClient,
				OrchestratorInformerFactory: chk.orchestratorInformerFactory,
			},
			ClusterID:   chk.clusterID,
			Config:      chk.orchestratorConfig,
			MsgGroupRef: chk.groupID,
		},
		stopCh:              chk.stopCh,
		manifestBuffer:      NewManifestBuffer(chk),
		activatedCollectors: map[string]struct{}{},
	}
	bundle.importCollectorsFromInventory()
	bundle.prepareExtraSyncTimeout()
	return bundle
}

// TestOrchestratorCheckSafeReSchedule close simulates the check being unscheduled and rescheduled again
func TestOrchestratorCheckSafeReSchedule(t *testing.T) {
	var wg sync.WaitGroup
	var scheme = kscheme.Scheme

	client := fake.NewSimpleClientset()
	vpaClient := vpa.NewSimpleClientset()
	crdClient := crd.NewSimpleClientset()
	crClient := cr.NewSimpleDynamicClient(scheme)
	cl := &apiserver.APIClient{InformerCl: client, VPAInformerClient: vpaClient, CRDInformerClient: crdClient, DynamicInformerCl: crClient}

	cfg := mockconfig.New(t)
	mockStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))

	fakeTagger := taggerfxmock.SetupFakeTagger(t)

	orchCheck := newCheck(cfg, mockStore, fakeTagger).(*OrchestratorCheck)
	mockSenderManager := mocksender.CreateDefaultDemultiplexer()
	_ = orchCheck.Configure(mockSenderManager, uint64(1), integration.Data{}, integration.Data{}, "test")
	orchCheck.apiClient = cl

	orchCheck.orchestratorInformerFactory = getOrchestratorInformerFactory(cl)
	bundle := newCollectorBundle(t, orchCheck)
	bundle.Initialize()

	wg.Add(2)

	// getting rescheduled.
	orchCheck.Cancel()

	bundle.runCfg.OrchestratorInformerFactory = getOrchestratorInformerFactory(cl)
	bundle.stopCh = make(chan struct{})
	bundle.initializeOnce = sync.Once{}
	bundle.Initialize()

	_, err := bundle.runCfg.OrchestratorInformerFactory.InformerFactory.Core().V1().Nodes().Informer().AddEventHandler(&cache.ResourceEventHandlerFuncs{
		AddFunc: func(_ interface{}) {
			wg.Done()
		},
	})
	assert.NoError(t, err)

	writeNode(t, client, "1")
	writeNode(t, client, "2")

	assert.True(t, waitTimeout(&wg, 2*time.Second))
}

func writeNode(t *testing.T, client *fake.Clientset, version string) {
	kubeN := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			ResourceVersion: version,
			UID:             types.UID("126430c6-5e57-11ea-91d5-42010a8400c6-" + version),
			Name:            "another-system-" + version,
		},
	}
	_, err := client.CoreV1().Nodes().Create(context.TODO(), &kubeN, metav1.CreateOptions{})
	assert.NoError(t, err)
}

// waitTimeout returns true if wg is completed and false if time is up
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestOrchCheckExtraTags(t *testing.T) {

	cfg := mockconfig.New(t)
	mockStore := fxutil.Test[workloadmetamock.Mock](t, fx.Options(
		core.MockBundle(),
		workloadmetafxmock.MockModule(workloadmeta.NewParams()),
	))
	mockSenderManager := mocksender.CreateDefaultDemultiplexer()

	t.Run("with no tags", func(t *testing.T) {
		fakeTagger := taggerfxmock.SetupFakeTagger(t)
		orchCheck := newCheck(cfg, mockStore, fakeTagger).(*OrchestratorCheck)

		_ = orchCheck.Configure(mockSenderManager, uint64(1), integration.Data{}, integration.Data{}, "test")
		assert.Empty(t, orchCheck.orchestratorConfig.ExtraTags)
	})

	t.Run("with tagger tags", func(t *testing.T) {
		fakeTagger := taggerfxmock.SetupFakeTagger(t)
		fakeTagger.SetGlobalTags([]string{"tag1:value1", "tag2:value2"}, nil, nil, nil)
		orchCheck := newCheck(cfg, mockStore, fakeTagger).(*OrchestratorCheck)

		_ = orchCheck.Configure(mockSenderManager, uint64(1), integration.Data{}, integration.Data{}, "test")
		assert.ElementsMatch(t, []string{"tag1:value1", "tag2:value2"}, orchCheck.orchestratorConfig.ExtraTags)
	})

	t.Run("with check tags", func(t *testing.T) {
		fakeTagger := taggerfxmock.SetupFakeTagger(t)
		orchCheck := newCheck(cfg, mockStore, fakeTagger).(*OrchestratorCheck)

		initConfigData := integration.Data(`{}`)
		instanceConfigData := integration.Data(`{}`)

		err := initConfigData.MergeAdditionalTags([]string{"init_tag1:value1", "init_tag2:value2"})
		assert.NoError(t, err)

		err = instanceConfigData.MergeAdditionalTags([]string{"instance_tag1:value1", "instance_tag2:value2"})
		assert.NoError(t, err)

		_ = orchCheck.Configure(mockSenderManager, uint64(1), initConfigData, instanceConfigData, "test")
		assert.ElementsMatch(t, []string{"init_tag1:value1", "init_tag2:value2", "instance_tag1:value1", "instance_tag2:value2"}, orchCheck.orchestratorConfig.ExtraTags)
	})

}
