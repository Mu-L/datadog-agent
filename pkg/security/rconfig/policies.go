// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package rconfig holds rconfig related files
package rconfig

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/skydive-project/go-debouncer"
	"go.uber.org/atomic"

	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	"github.com/DataDog/datadog-agent/pkg/config/remote/client"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	securityAgentRCPollInterval = time.Second * 1
	debounceDelay               = 5 * time.Second
)

// RCPolicyProvider defines a remote config policy provider
type RCPolicyProvider struct {
	sync.RWMutex

	client               *client.Client
	onNewPoliciesReadyCb func()
	lastDefaults         map[string]state.RawConfig
	lastCustoms          map[string]state.RawConfig
	debouncer            *debouncer.Debouncer
	dumpPolicies         bool
	setEnforcementCb     func(bool)

	isStarted *atomic.Bool
}

var _ rules.PolicyProvider = (*RCPolicyProvider)(nil)

// NewRCPolicyProvider returns a new Remote Config based policy provider
func NewRCPolicyProvider(dumpPolicies bool, setEnforcementCallback func(bool), ipc ipc.Component) (*RCPolicyProvider, error) {
	agentVersion, err := utils.GetAgentSemverVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to parse agent version: %w", err)
	}

	ipcAddress, err := pkgconfigsetup.GetIPCAddress(pkgconfigsetup.Datadog())
	if err != nil {
		return nil, fmt.Errorf("failed to get ipc address: %w", err)
	}

	c, err := client.NewGRPCClient(ipcAddress, pkgconfigsetup.GetIPCPort(),
		ipc.GetAuthToken(),
		ipc.GetTLSClientConfig(),
		client.WithAgent(agentName, agentVersion.String()),
		client.WithProducts(state.ProductCWSDD, state.ProductCWSCustom),
		client.WithPollInterval(securityAgentRCPollInterval),
		client.WithDirectorRootOverride(pkgconfigsetup.Datadog().GetString("site"), pkgconfigsetup.Datadog().GetString("remote_configuration.director_root")),
	)
	if err != nil {
		return nil, err
	}

	r := &RCPolicyProvider{
		client:           c,
		dumpPolicies:     dumpPolicies,
		setEnforcementCb: setEnforcementCallback,
		isStarted:        atomic.NewBool(false),
	}
	r.debouncer = debouncer.New(debounceDelay, r.onNewPoliciesReady)

	return r, nil
}

// Start starts the Remote Config policy provider and subscribes to updates
func (r *RCPolicyProvider) Start() {
	log.Info("remote-config policies provider started")

	r.debouncer.Start()

	r.client.SubscribeAll(state.ProductCWSDD, client.NewListener(r.rcDefaultsUpdateCallback, r.rcStateChanged))
	r.client.SubscribeAll(state.ProductCWSCustom, client.NewListener(r.rcCustomsUpdateCallback, r.rcStateChanged))

	r.client.Start()

	r.isStarted.Store(true)
}

func (r *RCPolicyProvider) rcStateChanged(state bool) {
	if r.setEnforcementCb != nil {
		r.setEnforcementCb(state)
	}
}

func (r *RCPolicyProvider) rcDefaultsUpdateCallback(configs map[string]state.RawConfig, _ func(string, state.ApplyStatus)) {
	r.Lock()
	if len(r.lastDefaults) == 0 && len(configs) == 0 {
		r.Unlock()
		return
	}
	r.lastDefaults = configs
	r.Unlock()

	log.Info("new policies from remote-config policy provider")

	r.debouncer.Call()
}

func (r *RCPolicyProvider) rcCustomsUpdateCallback(configs map[string]state.RawConfig, _ func(string, state.ApplyStatus)) {
	r.Lock()
	if len(r.lastCustoms) == 0 && len(configs) == 0 {
		r.Unlock()
		return
	}
	r.lastCustoms = configs
	r.Unlock()

	log.Info("new policies from remote-config policy provider")

	r.debouncer.Call()
}

func normalizePolicyName(name string) string {
	// remove the version
	_, normalized, found := strings.Cut(name, ".")
	if found {
		return normalized
	}
	return name
}

func writePolicy(name string, data []byte) (string, error) {
	file, err := os.CreateTemp("", name+"-")
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(data)
	return file.Name(), err
}

// LoadPolicies implements the PolicyProvider interface
func (r *RCPolicyProvider) LoadPolicies(macroFilters []rules.MacroFilter, ruleFilters []rules.RuleFilter) ([]*rules.Policy, *multierror.Error) {
	var policies []*rules.Policy
	var errs *multierror.Error

	r.RLock()
	defer r.RUnlock()

	load := func(policyType rules.PolicyType, id string, cfg []byte) error {
		if r.dumpPolicies {
			name, err := writePolicy(id, cfg)
			if err != nil {
				log.Errorf("unable to dump the policy: %s", err)
			} else {
				log.Infof("policy dumped : %s", name)
			}
		}

		pInfo := &rules.PolicyInfo{
			Name:   normalizePolicyName(id),
			Source: rules.PolicyProviderTypeRC,
			Type:   policyType,
		}
		reader := bytes.NewReader(cfg)
		policy, err := rules.LoadPolicy(pInfo, reader, macroFilters, ruleFilters)
		policies = append(policies, policy)
		return err
	}

	for _, cfgPath := range slices.Sorted(maps.Keys(r.lastDefaults)) {
		rawConfig := r.lastDefaults[cfgPath]

		if err := load(rules.DefaultPolicyType, rawConfig.Metadata.ID, rawConfig.Config); err != nil {
			r.client.UpdateApplyStatus(cfgPath, state.ApplyStatus{State: state.ApplyStateError, Error: err.Error()})
			errs = multierror.Append(errs, err)
		} else {
			r.client.UpdateApplyStatus(cfgPath, state.ApplyStatus{State: state.ApplyStateAcknowledged})
		}
	}

	for _, cfgPath := range slices.Sorted(maps.Keys(r.lastCustoms)) {
		rawConfig := r.lastCustoms[cfgPath]

		if err := load(rules.CustomPolicyType, rawConfig.Metadata.ID, rawConfig.Config); err != nil {
			r.client.UpdateApplyStatus(cfgPath, state.ApplyStatus{State: state.ApplyStateError, Error: err.Error()})
			errs = multierror.Append(errs, err)
		} else {
			r.client.UpdateApplyStatus(cfgPath, state.ApplyStatus{State: state.ApplyStateAcknowledged})
		}
	}

	return policies, errs
}

// SetOnNewPoliciesReadyCb implements the PolicyProvider interface
func (r *RCPolicyProvider) SetOnNewPoliciesReadyCb(cb func()) {
	r.onNewPoliciesReadyCb = cb
}

func (r *RCPolicyProvider) onNewPoliciesReady() {
	r.RLock()
	defer r.RUnlock()

	if r.onNewPoliciesReadyCb != nil {
		if r.setEnforcementCb != nil {
			r.setEnforcementCb(true)
		}

		r.onNewPoliciesReadyCb()
	}
}

// Close stops the client
func (r *RCPolicyProvider) Close() error {
	if !r.isStarted.Load() {
		return nil
	}

	r.debouncer.Stop()
	r.client.Close()
	return nil
}

// Type returns the type of this policy provider
func (r *RCPolicyProvider) Type() string {
	return rules.PolicyProviderTypeRC
}
