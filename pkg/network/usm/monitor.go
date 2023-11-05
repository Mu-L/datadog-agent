// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/atomic"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http2"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/kafka"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type monitorState = string

const (
	Disabled   monitorState = "Disabled"
	Running    monitorState = "Running"
	NotRunning monitorState = "Not Running"

	connProtoTTL              = 3 * time.Minute
	connProtoCleaningInterval = 5 * time.Minute

	// ELF section of the BPF_PROG_TYPE_SOCKET_FILTER program used
	// to classify protocols and dispatch the correct handlers.
	protocolDispatcherSocketFilterFunction = "socket__protocol_dispatcher"
	connectionStatesMap                    = "connection_states"

	// maxActive configures the maximum number of instances of the
	// kretprobe-probed functions handled simultaneously.  This value should be
	// enough for typical workloads (e.g. some amount of processes blocked on
	// the accept syscall).
	maxActive = 128
	probeUID  = "http"

	usmAssetName      = "usm.o"
	usmDebugAssetName = "usm-debug.o"
)

var (
	state        = Disabled
	startupError error

	errNoProtocols = errors.New("no protocol monitors were initialised")

	// knownProtocols holds all known protocols supported by USM to initialize.
	knownProtocols = []*protocols.ProtocolSpec{
		http.Spec,
		http2.Spec,
		kafka.Spec,
		javaTLSSpec,
		// opensslSpec is unique, as we're modifying its factory during runtime to allow getting more parameters in the
		// factory.
		opensslSpec,
		goTLSSpec,
	}

	mapsList = []*manager.Map{
		{
			Name: protocols.TLSDispatcherProgramsMap,
		},
		{
			Name: protocols.ProtocolDispatcherProgramsMap,
		},
		{
			Name: connectionStatesMap,
		},
	}

	probeList = []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "kprobe__tcp_sendmsg",
				UID:          probeUID,
			},
			KProbeMaxActive: maxActive,
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: "tracepoint__net__netif_receive_skb",
				UID:          probeUID,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: protocolDispatcherSocketFilterFunction,
				UID:          probeUID,
			},
		},
	}
)

// Monitor is responsible for:
// * Creating a raw socket and attaching an eBPF filter to it;
// * Consuming HTTP transaction "events" that are sent from Kernel space;
// * Aggregating and emitting metrics based on the received HTTP transactions;
type Monitor struct {
	cfg *config.Config

	ebpfProgram *ebpfProgram

	processMonitor *monitor.ProcessMonitor

	// termination
	closeFilterFn func()

	lastUpdateTime *atomic.Int64

	// Used for connection_protocol data expiration
	mapCleaner            *ddebpf.MapCleaner
	connectionProtocolMap *ebpf.Map
}

// NewMonitor returns a new Monitor instance
func NewMonitor(c *config.Config, connectionProtocolMap, sockFD *ebpf.Map, bpfTelemetry *errtelemetry.EBPFTelemetry) (m *Monitor, err error) {
	defer func() {
		// capture error and wrap it
		if err != nil {
			state = NotRunning
			err = fmt.Errorf("could not initialize USM: %w", err)
			startupError = err
		}
	}()

	mgr, err := newEBPFProgram(c, sockFD, connectionProtocolMap, bpfTelemetry)
	if err != nil {
		return nil, fmt.Errorf("error setting up ebpf program: %w", err)
	}

	if len(mgr.enabledProtocols) == 0 {
		state = Disabled
		log.Debug("not enabling USM as no protocols monitoring were enabled.")
		return nil, nil
	}

	if err := mgr.Init(); err != nil {
		return nil, fmt.Errorf("error initializing ebpf program: %w", err)
	}

	filter, _ := mgr.GetProbe(manager.ProbeIdentificationPair{EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID})
	if filter == nil {
		return nil, fmt.Errorf("error retrieving socket filter")
	}
	ebpfcheck.AddNameMappings(mgr.Manager.Manager, "usm_monitor")

	closeFilterFn, err := filterpkg.HeadlessSocketFilter(c, filter)
	if err != nil {
		return nil, fmt.Errorf("error enabling traffic inspection: %s", err)
	}

	processMonitor := monitor.GetProcessMonitor()

	state = Running

	usmMonitor := &Monitor{
		cfg:                   c,
		ebpfProgram:           mgr,
		closeFilterFn:         closeFilterFn,
		processMonitor:        processMonitor,
		connectionProtocolMap: connectionProtocolMap,
	}

	usmMonitor.lastUpdateTime = atomic.NewInt64(time.Now().Unix())

	return usmMonitor, nil
}

func (m *Monitor) setupMapCleaner() (*ddebpf.MapCleaner, error) {
	mapCleaner, err := ddebpf.NewMapCleaner(m.connectionProtocolMap, new(netebpf.ConnTuple), new(netebpf.ProtocolStackWrapper))
	if err != nil {
		return nil, err
	}

	ttl := connProtoTTL.Nanoseconds()
	mapCleaner.Clean(connProtoCleaningInterval, func(now int64, key, val interface{}) bool {
		protoStack, ok := val.(*netebpf.ProtocolStackWrapper)
		if !ok {
			return false
		}

		updated := int64(protoStack.Updated)
		return (now - updated) > ttl
	})

	return mapCleaner, nil
}

// Start USM monitor.
func (m *Monitor) Start() error {
	if m == nil {
		return nil
	}

	var err error

	defer func() {
		if err != nil {
			if errors.Is(err, syscall.ENOMEM) {
				err = fmt.Errorf("could not enable usm monitoring: not enough memory to attach http ebpf socket filter. please consider raising the limit via sysctl -w net.core.optmem_max=<LIMIT>")
			} else {
				err = fmt.Errorf("could not enable USM: %s", err)
			}

			m.Stop()

			startupError = err
		}
	}()

	// setup map cleaner
	mapCleaner, err := m.setupMapCleaner()
	if err != nil {
		log.Errorf("error creating map cleaner: %s", err)
	} else {
		m.mapCleaner = mapCleaner
	}

	err = m.ebpfProgram.Start()
	if err != nil {
		m.mapCleaner.Stop()
		return err
	}

	// Need to explicitly save the error in `err` so the defer function could save the startup error.
	if m.cfg.EnableNativeTLSMonitoring || m.cfg.EnableGoTLSSupport || m.cfg.EnableJavaTLSSupport || m.cfg.EnableIstioMonitoring {
		err = m.processMonitor.Initialize()
	}

	return err
}

func (m *Monitor) GetUSMStats() map[string]interface{} {
	response := map[string]interface{}{
		"state": state,
	}

	if startupError != nil {
		response["error"] = startupError.Error()
	}

	if m != nil {
		response["last_check"] = m.lastUpdateTime
	}
	return response
}

func (m *Monitor) GetProtocolStats() map[protocols.ProtocolType]interface{} {
	if m == nil {
		return nil
	}

	defer func() {
		// Update update time
		now := time.Now().Unix()
		m.lastUpdateTime.Swap(now)
		telemetry.ReportPrometheus()
	}()

	return m.ebpfProgram.getProtocolStats()
}

// Stop HTTP monitoring
func (m *Monitor) Stop() {
	if m == nil {
		return
	}

	m.processMonitor.Stop()

	ebpfcheck.RemoveNameMappings(m.ebpfProgram.Manager.Manager)

	m.mapCleaner.Stop()
	m.ebpfProgram.Close()
	m.closeFilterFn()
}

// DumpMaps dumps the maps associated with the monitor
func (m *Monitor) DumpMaps(maps ...string) (string, error) {
	return m.ebpfProgram.DumpMaps(maps...)
}
