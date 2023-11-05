// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"fmt"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"math"

	manager "github.com/DataDog/ebpf-manager"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/network"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/offsetguess"
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func (e *ebpfProgram) Init() error {
	var err error
	defer func() {
		if err != nil {
			e.buildMode = ""
		}
	}()

	e.DumpHandler = e.dumpMapsHandler

	if e.cfg.EnableCORE {
		e.buildMode = buildmode.CORE
		err = e.initCORE()
		if err == nil {
			return nil
		}

		if !e.cfg.AllowRuntimeCompiledFallback && !e.cfg.AllowPrecompiledFallback {
			return fmt.Errorf("co-re load failed: %w", err)
		}
		log.Warnf("co-re load failed. attempting fallback: %s", err)
	}

	if e.cfg.EnableRuntimeCompiler || (err != nil && e.cfg.AllowRuntimeCompiledFallback) {
		e.buildMode = buildmode.RuntimeCompiled
		err = e.initRuntimeCompiler()
		if err == nil {
			return nil
		}

		if !e.cfg.AllowPrecompiledFallback {
			return fmt.Errorf("runtime compilation failed: %w", err)
		}
		log.Warnf("runtime compilation failed: attempting fallback: %s", err)
	}

	e.buildMode = buildmode.Prebuilt
	err = e.initPrebuilt()
	return err
}

func (e *ebpfProgram) Start() error {
	e.enabledProtocols = e.executePerProtocol(e.enabledProtocols, "pre-start",
		func(protocol protocols.Protocol, m *manager.Manager) error { return protocol.PreStart(m) },
		func(protocols.Protocol, *manager.Manager) {})

	// No protocols could be enabled, abort.
	if len(e.enabledProtocols) == 0 {
		return errNoProtocols
	}

	err := e.Manager.Start()
	if err != nil {
		return err
	}

	e.enabledProtocols = e.executePerProtocol(e.enabledProtocols, "post-start",
		func(protocol protocols.Protocol, m *manager.Manager) error { return protocol.PostStart(m) },
		func(protocol protocols.Protocol, m *manager.Manager) { protocol.Stop(m) })

	// We check again if there are protocols that could be enabled, and abort if
	// it is not the case.
	if len(e.enabledProtocols) == 0 {
		err = e.Close()
		if err != nil {
			log.Errorf("error during USM shutdown: %s", err)
		}

		return errNoProtocols
	}

	for _, protocolName := range e.enabledProtocols {
		log.Infof("enabled USM protocol: %s", protocolName.Instance.Name())
	}

	return nil
}

func (e *ebpfProgram) Close() error {
	stopProtocolWrapper := func(protocol protocols.Protocol, m *manager.Manager) error {
		protocol.Stop(m)
		return nil
	}
	e.executePerProtocol(e.enabledProtocols, "stop", stopProtocolWrapper, nil)
	return e.Stop(manager.CleanAll)
}

func (e *ebpfProgram) initCORE() error {
	assetName := usmAssetName
	if e.cfg.BPFDebug {
		assetName = usmDebugAssetName
	}

	return ddebpf.LoadCOREAsset(assetName, e.init)
}

func (e *ebpfProgram) initRuntimeCompiler() error {
	bc, err := getRuntimeCompiledUSM(e.cfg)
	if err != nil {
		return err
	}
	defer bc.Close()
	return e.init(bc, manager.Options{})
}

func (e *ebpfProgram) initPrebuilt() error {
	bc, err := netebpf.ReadHTTPModule(e.cfg.BPFDir, e.cfg.BPFDebug)
	if err != nil {
		return err
	}
	defer bc.Close()

	var offsets []manager.ConstantEditor
	if offsets, err = offsetguess.TracerOffsets.Offsets(e.cfg); err != nil {
		return err
	}

	return e.init(bc, manager.Options{ConstantEditors: offsets})
}

// configureManagerWithSupportedProtocols given a protocol list, we're adding for each protocol its Maps, Probes and
// TailCalls to the program's lists. Also, we're providing a cleanup method (the return value) which allows removal
// of the elements we added in case of a failure in the initialization.
func (e *ebpfProgram) configureManagerWithSupportedProtocols(protocols []*protocols.ProtocolSpec) func() {
	for _, spec := range protocols {
		e.Maps = append(e.Maps, spec.Maps...)
		e.Probes = append(e.Probes, spec.Probes...)
		e.tailCallRouter = append(e.tailCallRouter, spec.TailCalls...)
	}
	return func() {
		for _, spec := range protocols {
			e.Maps = e.Maps[:len(e.Maps)-len(spec.Maps)]
			e.Probes = e.Probes[:len(e.Probes)-len(spec.Probes)]
			e.tailCallRouter = e.tailCallRouter[:len(e.tailCallRouter)-len(spec.TailCalls)]
		}
	}
}

func (e *ebpfProgram) init(buf bytecode.AssetReader, options manager.Options) error {
	kprobeAttachMethod := manager.AttachKprobeWithPerfEventOpen
	if e.cfg.AttachKprobesWithKprobeEventsABI {
		kprobeAttachMethod = manager.AttachKprobeWithKprobeEvents
	}

	options.RLimit = &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	options.MapSpecEditors = map[string]manager.MapSpecEditor{
		connectionStatesMap: {
			MaxEntries: e.cfg.MaxTrackedConnections,
			EditorFlag: manager.EditMaxEntries,
		},
	}

	options.MapSpecEditors[probes.ConnectionProtocolMap] = manager.MapSpecEditor{
		MaxEntries: e.cfg.MaxTrackedConnections,
		EditorFlag: manager.EditMaxEntries,
	}
	if e.connectionProtocolMap != nil {
		if options.MapEditors == nil {
			options.MapEditors = make(map[string]*ebpf.Map)
		}
		options.MapEditors[probes.ConnectionProtocolMap] = e.connectionProtocolMap
	}

	begin, end := network.EphemeralRange()
	options.ConstantEditors = append(options.ConstantEditors,
		manager.ConstantEditor{Name: "ephemeral_range_begin", Value: uint64(begin)},
		manager.ConstantEditor{Name: "ephemeral_range_end", Value: uint64(end)})

	options.ActivatedProbes = []manager.ProbesSelector{
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: protocolDispatcherSocketFilterFunction,
				UID:          probeUID,
			},
		},
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe__tcp_sendmsg",
				UID:          probeUID,
			},
		},
		&manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint__net__netif_receive_skb",
				UID:          probeUID,
			},
		},
	}

	// Some parts of USM (https capturing, and part of the classification) use `read_conn_tuple`, and has some if
	// clauses that handled IPV6, for USM we care (ATM) only from TCP connections, so adding the sole config about tcpv6.
	utils.AddBoolConst(&options, e.cfg.CollectTCPv6Conns, "tcpv6_enabled")

	options.DefaultKprobeAttachMethod = kprobeAttachMethod
	options.VerifierOptions.Programs.LogSize = 10 * 1024 * 1024

	supported, notSupported := e.getProtocolsForBuildMode()
	cleanup := e.configureManagerWithSupportedProtocols(supported)
	options.TailCallRouter = e.tailCallRouter
	for _, p := range supported {
		p.Instance.ConfigureOptions(e.Manager.Manager, &options)
	}

	// Add excluded functions from disabled protocols
	for _, p := range notSupported {
		for _, m := range p.Maps {
			// Unused maps still need to have a non-zero size
			options.MapSpecEditors[m.Name] = manager.MapSpecEditor{
				MaxEntries: uint32(1),
				EditorFlag: manager.EditMaxEntries,
			}

			log.Debugf("disabled map: %v", m.Name)
		}

		for _, probe := range p.Probes {
			options.ExcludedFunctions = append(options.ExcludedFunctions, probe.ProbeIdentificationPair.EBPFFuncName)
		}

		for _, tc := range p.TailCalls {
			options.ExcludedFunctions = append(options.ExcludedFunctions, tc.ProbeIdentificationPair.EBPFFuncName)
		}
	}

	var undefinedProbes []manager.ProbeIdentificationPair
	for _, tc := range e.tailCallRouter {
		undefinedProbes = append(undefinedProbes, tc.ProbeIdentificationPair)
	}

	e.InstructionPatcher = func(m *manager.Manager) error {
		return errtelemetry.PatchEBPFTelemetry(m, true, undefinedProbes)
	}

	err := e.InitWithOptions(buf, options)
	if err != nil {
		cleanup()
	} else {
		// Update the protocols lists to reflect the ones we actually enabled
		e.enabledProtocols = supported
		e.disabledProtocols = notSupported
	}

	return err
}
