// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package probe holds probe related files
package probe

import (
	"context"
	json "encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/probe/kfilters"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

type DarwinProbe struct {
	fieldHandlers *FieldHandlers
	ctx           context.Context
	cancelFnc     context.CancelFunc
}

func NewDarwinProbe(p *Probe, config *config.Config, opts Opts) (*DarwinProbe, error) {
	ctx, cancelFnc := context.WithCancel(context.Background())
	return &DarwinProbe{
		fieldHandlers: &FieldHandlers{},
		ctx:           ctx,
		cancelFnc:     cancelFnc,
	}, nil
}

func (dp *DarwinProbe) Setup() error { return nil }
func (dp *DarwinProbe) Init() error  { return nil }
func (dp *DarwinProbe) Start() error {
	cmd := exec.Command("/usr/bin/eslogger", "exec")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(stdout)

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-dp.ctx.Done():
				break
			}
		}

		cmd.Process.Kill()
		cmd.Wait()
	}()

	go func() {
		var value ESEvent
		for {
			err := decoder.Decode(&value)
			if err == io.EOF {
				break
			}

			fmt.Println(value)
		}
	}()

	return nil
}

func (dp *DarwinProbe) Stop() {
	dp.cancelFnc()
}
func (dp *DarwinProbe) SendStats() error { return nil }
func (dp *DarwinProbe) Snapshot() error  { return nil }
func (dp *DarwinProbe) Close() error     { return nil }
func (dp *DarwinProbe) NewModel() *model.Model {
	return NewDarwinModel()
}
func (dp *DarwinProbe) DumpDiscarders() (string, error) {
	return "", errors.New("not supported")
}
func (dp *DarwinProbe) FlushDiscarders() error { return nil }
func (dp *DarwinProbe) ApplyRuleSet(_ *rules.RuleSet) (*kfilters.ApplyRuleSetReport, error) {
	return &kfilters.ApplyRuleSetReport{}, nil
}
func (dp *DarwinProbe) OnNewDiscarder(_ *rules.RuleSet, _ *model.Event, _ eval.Field, _ eval.EventType) {
}
func (dp *DarwinProbe) HandleActions(_ *rules.Rule, _ eval.Event) {}
func (dp *DarwinProbe) NewEvent() *model.Event {
	return NewDarwinEvent(dp.fieldHandlers)
}
func (dp *DarwinProbe) GetFieldHandlers() model.FieldHandlers {
	return dp.fieldHandlers
}
func (dp *DarwinProbe) DumpProcessCache(_ bool) (string, error)              { return "", nil }
func (dp *DarwinProbe) AddDiscarderPushedCallback(_ DiscarderPushedCallback) {}
func (dp *DarwinProbe) GetEventTags(_ string) []string                       { return nil }

// NewProbe instantiates a new runtime security agent probe
func NewProbe(config *config.Config, opts Opts) (*Probe, error) {
	opts.normalize()

	p := &Probe{
		Opts:         opts,
		Config:       config,
		StatsdClient: opts.StatsdClient,
		scrubber:     newProcScrubber(config.Probe.CustomSensitiveWords),
	}

	pp, err := NewDarwinProbe(p, config, opts)
	if err != nil {
		return nil, err
	}
	p.PlatformProbe = pp

	p.event = p.PlatformProbe.NewEvent()

	// be sure to zero the probe event before everything else
	p.zeroEvent()

	return p, nil
}

type ESEvent struct {
	Event struct {
		Exec struct {
			Args   []string `json:"args"`
			Target struct {
				Executable struct {
					Path string `json:"path"`
				} `json:"executable"`
			} `json:"target"`
		} `json:"exec"`
	} `json:"event"`
}
