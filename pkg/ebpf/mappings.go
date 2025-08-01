// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
)

var mappingLock sync.RWMutex

var mapNameMapping = make(map[uint32]string)
var mapModuleMapping = make(map[uint32]string)

var progNameMapping = make(map[uint32]string)
var progModuleMapping = make(map[uint32]string)

var probeIDToFDMappings = make(map[ebpf.ProgramID]uint32)

var progIgnoredIDs = make(map[ebpf.ProgramID]struct{})

// errNoMapping is returned when a give map or program id is
// not tracked as part of system-probe/security-agent
var errNoMapping = errors.New("no mapping found for given id")

// AddProgramNameMapping manually adds a program name mapping
func AddProgramNameMapping(progid uint32, name string, module string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	progNameMapping[progid] = name
	progModuleMapping[progid] = module
}

// RemoveProgramID manually removes a program name mapping
func RemoveProgramID(progID uint32, expectedModule string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	if progModuleMapping[progID] == expectedModule {
		delete(progNameMapping, progID)
		delete(progModuleMapping, progID)
	}
}

// ClearProgramIDMappings clears all name mappings for a given module
func ClearProgramIDMappings(module string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	for progID, progModule := range progModuleMapping {
		if progModule == module {
			delete(progNameMapping, progID)
			delete(progModuleMapping, progID)
			delete(probeIDToFDMappings, ebpf.ProgramID(progID))
		}
	}

	for mapID, mapModule := range mapModuleMapping {
		if mapModule == module {
			delete(mapNameMapping, mapID)
			delete(mapModuleMapping, mapID)
		}
	}
}

// AddNameMappings adds the full name mappings for ebpf maps in the manager
func AddNameMappings(mgr *manager.Manager, module string) {
	maps, err := mgr.GetMaps()
	if err != nil {
		return
	}

	progs, err := mgr.GetPrograms()
	if err != nil {
		return
	}

	mappingLock.Lock()
	defer mappingLock.Unlock()

	iterateMaps(maps, func(mapid uint32, name string) {
		mapNameMapping[mapid] = name
		mapModuleMapping[mapid] = module
	})

	iterateProgs(progs, func(progid uint32, name string) {
		progNameMapping[progid] = name
		progModuleMapping[progid] = module
	})
}

// AddNameMappingsCollection adds the full name mappings for ebpf maps in the collection
func AddNameMappingsCollection(coll *ebpf.Collection, module string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	iterateMaps(coll.Maps, func(mapid uint32, name string) {
		mapNameMapping[mapid] = name
		mapModuleMapping[mapid] = module
	})
	iterateProgs(coll.Programs, func(progid uint32, name string) {
		progNameMapping[progid] = name
		progModuleMapping[progid] = module
	})
}

// AddNameMappingsForMap adds the full name mappings for the provided ebpf map
func AddNameMappingsForMap(m *ebpf.Map, name, module string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	registerMap(m, func(mapid uint32) {
		mapNameMapping[mapid] = name
		mapModuleMapping[mapid] = module
	})
}

// AddNameMappingsForProgram adds the full name mappings for the provided ebpf program
func AddNameMappingsForProgram(p *ebpf.Program, name, module string) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	registerProgram(p, func(progid uint32) {
		progNameMapping[progid] = name
		progModuleMapping[progid] = module

	})
}

func getMappingFromID(id uint32, m map[uint32]string) (string, error) {
	mappingLock.RLock()
	defer mappingLock.RUnlock()

	name, ok := m[id]
	if !ok {
		return "", errNoMapping
	}

	return name, nil
}

// GetMapNameFromMapID returns the map name for the given id
func GetMapNameFromMapID(id uint32) (string, error) {
	return getMappingFromID(id, mapNameMapping)
}

// GetModuleFromMapID returns the module name for the map with the given id
func GetModuleFromMapID(id uint32) (string, error) {
	return getMappingFromID(id, mapModuleMapping)

}

// GetProgNameFromProgID returns the program name for the given id
func GetProgNameFromProgID(id uint32) (string, error) {
	return getMappingFromID(id, progNameMapping)
}

// GetModuleFromProgID returns the module name for the program with the given id
func GetModuleFromProgID(id uint32) (string, error) {
	return getMappingFromID(id, progModuleMapping)
}

// GetPerfEventFDByProbeID returns the fd mapped for a probe or an error if no mappings exists
func GetPerfEventFDByProbeID(probeID ebpf.ProgramID) (uint32, error) {
	mappingLock.RLock()
	defer mappingLock.RUnlock()

	fd, ok := probeIDToFDMappings[probeID]
	if ok {
		return fd, nil
	}

	return 0, fmt.Errorf("no fd exists for probe with id %d", probeID)
}

// RemoveNameMappings removes the full name mappings for ebpf maps in the manager
func RemoveNameMappings(mgr *manager.Manager) {
	maps, err := mgr.GetMaps()
	if err != nil {
		return
	}

	mappingLock.Lock()
	defer mappingLock.Unlock()

	iterateMaps(maps, func(mapid uint32, _ string) {
		delete(mapNameMapping, mapid)
		delete(mapModuleMapping, mapid)
	})

	progs, err := mgr.GetPrograms()
	if err != nil {
		return
	}
	iterateProgs(progs, func(progid uint32, _ string) {
		delete(progNameMapping, progid)
		delete(progModuleMapping, progid)
	})

	for _, p := range mgr.Probes {
		// ebpf-manager functions like DetachHook can modify backing array of our copy of Probes out from under us
		if p == nil {
			continue
		}
		progid := p.ID()
		delete(progNameMapping, progid)
		delete(progModuleMapping, progid)
	}
}

// RemoveNameMappingsCollection removes the full name mappings for ebpf maps in the collection
func RemoveNameMappingsCollection(coll *ebpf.Collection) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	iterateMaps(coll.Maps, func(mapid uint32, _ string) {
		delete(mapNameMapping, mapid)
		delete(mapModuleMapping, mapid)
	})
	iterateProgs(coll.Programs, func(progid uint32, _ string) {
		delete(progNameMapping, progid)
		delete(progModuleMapping, progid)
	})
}

func registerMap(m *ebpf.Map, mapFn func(mapid uint32)) {
	if info, err := m.Info(); err == nil {
		if mapid, ok := info.ID(); ok {
			mapFn(uint32(mapid))
		}
	}
}

func iterateMaps(maps map[string]*ebpf.Map, mapFn func(mapid uint32, name string)) {
	for name, m := range maps {
		registerMap(m, func(progid uint32) {
			mapFn(progid, name)
		})
	}
}

func registerProgram(p *ebpf.Program, mapFn func(progid uint32)) {
	if info, err := p.Info(); err == nil {
		if progid, ok := info.ID(); ok {
			mapFn(uint32(progid))
		}
	}
}

func iterateProgs(progs map[string]*ebpf.Program, mapFn func(progid uint32, name string)) {
	for name, p := range progs {
		registerProgram(p, func(progid uint32) {
			mapFn(progid, name)
		})
	}
}

// AddIgnoredProgramID adds a program ID to the list of ignored programs
func AddIgnoredProgramID(id ebpf.ProgramID) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	progIgnoredIDs[id] = struct{}{}
}

// RemoveIgnoredProgramID removes a program ID from the list of ignored programs
func RemoveIgnoredProgramID(id ebpf.ProgramID) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	progIgnoredIDs[id] = struct{}{}
}

// IsProgramIDIgnored returns true if this program ID should be ignored
func IsProgramIDIgnored(id ebpf.ProgramID) bool {
	mappingLock.RLock()
	defer mappingLock.RUnlock()

	_, ok := progIgnoredIDs[id]
	return ok
}

// AddProbeFDMappings creates mappings between a program and its perf event fd
func AddProbeFDMappings(mgr *manager.Manager) {
	mappingLock.Lock()
	defer mappingLock.Unlock()

	// GetProbes returns a copy of the probes. We use this because mgr.Probes is mutable
	// and so may change from underneath us.
	probes := mgr.GetProbes()
	for _, p := range probes {
		if p == nil || !p.IsRunning() {
			continue
		}

		specs, _, err := mgr.GetProgramSpec(p.ProbeIdentificationPair)
		if err != nil || len(specs) == 0 {
			continue
		}

		if specs[0].Type != ebpf.Kprobe {
			continue
		}
		progType, _, _ := strings.Cut(specs[0].SectionName, "/")
		switch progType {
		case "uprobe", "uretprobe":
			continue
		}

		fd, err := p.PerfEventFD()
		if err == nil {
			probeIDToFDMappings[ebpf.ProgramID(p.ID())] = fd
		}
	}
}

func resetMapping[K comparable, V any](m map[K]V) {
	for key := range m {
		delete(m, key)
	}
}

// ResetAllMappings removes all mappings. This is useful in tests to reset state
func ResetAllMappings() {
	resetMapping(mapNameMapping)
	resetMapping(mapModuleMapping)
	resetMapping(progNameMapping)
	resetMapping(progModuleMapping)
	resetMapping(probeIDToFDMappings)
	resetMapping(progIgnoredIDs)
}
