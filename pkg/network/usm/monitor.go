// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
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

	mgr *errtelemetry.Manager

	processMonitor *monitor.ProcessMonitor

	// termination
	closeFilterFn func()

	lastUpdateTime *atomic.Int64

	// Used for connection_protocol data expiration
	mapCleaner            *ddebpf.MapCleaner
	connectionProtocolMap *ebpf.Map

	tailCallRouter []manager.TailCallRoute

	enabledProtocols  []*protocols.ProtocolSpec
	disabledProtocols []*protocols.ProtocolSpec

	buildMode buildmode.Type
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

	usmMonitor := &Monitor{
		cfg:                   c,
		mgr:                   newManager(bpfTelemetry),
		connectionProtocolMap: connectionProtocolMap,
	}

	opensslSpec.Factory = newSSLProgramProtocolFactory(usmMonitor.mgr.Manager, sockFD, bpfTelemetry)
	goTLSSpec.Factory = newGoTLSProgramProtocolFactory(usmMonitor.mgr.Manager, sockFD)

	if err := usmMonitor.initProtocols(c); err != nil {
		return nil, err
	}

	if len(usmMonitor.enabledProtocols) == 0 {
		state = Disabled
		log.Debug("not enabling USM as no protocols monitoring were enabled.")
		return nil, nil
	}

	// TODO: change
	if err := usmMonitor.mgr.Init(); err != nil {
		return nil, fmt.Errorf("error initializing ebpf program: %w", err)
	}

	filter, _ := usmMonitor.mgr.GetProbe(manager.ProbeIdentificationPair{EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID})
	if filter == nil {
		return nil, fmt.Errorf("error retrieving socket filter")
	}
	ebpfcheck.AddNameMappings(usmMonitor.mgr.Manager, "usm_monitor")

	usmMonitor.closeFilterFn, err = filterpkg.HeadlessSocketFilter(c, filter)
	if err != nil {
		return nil, fmt.Errorf("error enabling traffic inspection: %s", err)
	}

	usmMonitor.processMonitor = monitor.GetProcessMonitor()

	state = Running

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

	ret := make(map[protocols.ProtocolType]interface{})

	for _, protocol := range m.enabledProtocols {
		ps := protocol.Instance.GetStats()
		if ps != nil {
			ret[ps.Type] = ps.Stats
		}
	}

	return ret
}

// Stop HTTP monitoring
func (m *Monitor) Stop() {
	if m == nil {
		return
	}

	m.processMonitor.Stop()

	ebpfcheck.RemoveNameMappings(m.mgr.Manager)

	m.mapCleaner.Stop()
	m.ebpfProgram.Close()
	m.closeFilterFn()
}

// DumpMaps dumps the maps associated with the monitor
func (m *Monitor) DumpMaps(maps ...string) (string, error) {
	return m.mgr.DumpMaps(maps...)
}

func newManager(bpfTelemetry *errtelemetry.EBPFTelemetry) *errtelemetry.Manager {
	return errtelemetry.NewManager(&manager.Manager{Maps: mapsList, Probes: probeList}, bpfTelemetry)
}

// executePerProtocol runs the given callback (`cb`) for every protocol in the given list (`protocolList`).
// If the callback failed, then we call the error callback (`errorCb`). Eventually returning a list of protocols which
// successfully executed the callback.
func (m *Monitor) executePerProtocol(protocolList []*protocols.ProtocolSpec, phaseName string, cb func(protocols.Protocol, *manager.Manager) error, errorCb func(protocols.Protocol, *manager.Manager)) []*protocols.ProtocolSpec {
	// Deleting from an array while iterating it is not a simple task. Instead, every successfully enabled protocol,
	// we'll keep in a temporary copy and return it at the end.
	res := make([]*protocols.ProtocolSpec, 0)
	for _, protocol := range protocolList {
		if err := cb(protocol.Instance, m.mgr.Manager); err != nil {
			if errorCb != nil {
				errorCb(protocol.Instance, m.mgr.Manager)
			}
			log.Errorf("could not complete %q phase of %q monitoring: %s", phaseName, protocol.Instance.Name(), err)
			continue
		}
		res = append(res, protocol)
	}
	return res
}

// initProtocols takes the network configuration `c` and uses it to initialise
// the enabled protocols' monitoring, and configures the ebpf-manager `mgr`
// accordingly.
//
// For each enabled protocols, a protocol-specific instance of the Protocol
// interface is initialised, and the required maps and tail calls routers are setup
// in the manager.
//
// If a protocol is not enabled, its tail calls are instead added to the list of
// excluded functions for them to be patched out by ebpf-manager on startup.
//
// It returns:
// - a slice containing instances of the Protocol interface for each enabled protocol support
// - a slice containing pointers to the protocol specs of disabled protocols.
// - an error value, which is non-nil if an error occurred while initialising a protocol
func (m *Monitor) initProtocols(c *config.Config) error {
	m.enabledProtocols = make([]*protocols.ProtocolSpec, 0)
	m.disabledProtocols = make([]*protocols.ProtocolSpec, 0)

	for _, spec := range knownProtocols {
		protocol, err := spec.Factory(c)
		if err != nil {
			return &errNotSupported{err}
		}

		if protocol != nil {
			spec.Instance = protocol
			m.enabledProtocols = append(m.enabledProtocols, spec)

			log.Infof("%v monitoring enabled", protocol.Name())
		} else {
			m.disabledProtocols = append(m.disabledProtocols, spec)
		}
	}

	return nil
}

// getProtocolsForBuildMode returns 2 lists - supported and not-supported protocol lists.
// 1. Supported - enabled protocols which are supported by the current build mode (`e.buildMode`)
// 2. Not Supported - disabled protocols, and enabled protocols which are not supported by the current build mode.
func (m *Monitor) getProtocolsForBuildMode() ([]*protocols.ProtocolSpec, []*protocols.ProtocolSpec) {
	supported := make([]*protocols.ProtocolSpec, 0)
	notSupported := make([]*protocols.ProtocolSpec, 0, len(m.disabledProtocols))
	notSupported = append(notSupported, m.disabledProtocols...)

	for _, p := range m.enabledProtocols {
		if p.Instance.IsBuildModeSupported(m.buildMode) {
			supported = append(supported, p)
		} else {
			notSupported = append(notSupported, p)
		}
	}

	return supported, notSupported
}

func (m *Monitor) dumpMapsHandler(_ *manager.Manager, mapName string, currentMap *ebpf.Map) string {
	var output strings.Builder

	switch mapName {
	case connectionStatesMap: // maps/connection_states (BPF_MAP_TYPE_HASH), key C.conn_tuple_t, value C.__u32
		output.WriteString("Map: '" + mapName + "', key: 'C.conn_tuple_t', value: 'C.__u32'\n")
		iter := currentMap.Iterate()
		var key http.ConnTuple
		var value uint32
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			output.WriteString(spew.Sdump(key, value))
		}

	default: // Go through enabled protocols in case one of them now how to handle the current map
		for _, p := range m.enabledProtocols {
			p.Instance.DumpMaps(&output, mapName, currentMap)
		}
	}
	return output.String()
}
