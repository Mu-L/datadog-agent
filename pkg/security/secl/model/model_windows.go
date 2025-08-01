// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:generate accessors -tags windows -types-file model.go -output accessors_windows.go -field-handlers field_handlers_windows.go -doc ../../../../docs/cloud-workload-security/secl_windows.json -field-accessors-output field_accessors_windows.go

// Package model holds model related files
package model

import (
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

// NewEvent returns a new Event
func (m *Model) NewEvent() eval.Event {
	return &Event{
		BaseEvent: BaseEvent{
			ContainerContext: &ContainerContext{},
			Os:               runtime.GOOS,
		},
	}
}

// NewFakeEvent returns a new event using the default field handlers
func NewFakeEvent() *Event {
	return &Event{
		BaseEvent: BaseEvent{
			FieldHandlers:    &FakeFieldHandlers{},
			ContainerContext: &ContainerContext{},
			Os:               runtime.GOOS,
		},
	}
}

// ResolveProcessCacheEntryFromPID stub implementation
func (fh *FakeFieldHandlers) ResolveProcessCacheEntryFromPID(pid uint32) *ProcessCacheEntry {
	return GetPlaceholderProcessCacheEntry(pid)
}

var processContextZero = ProcessCacheEntry{}

// GetPlaceholderProcessCacheEntry returns an empty process cache entry for failed process resolutions
func GetPlaceholderProcessCacheEntry(pid uint32) *ProcessCacheEntry {
	processContextZero.Pid = pid
	return &processContextZero
}

// ValidateField validates the value of a field
func (m *Model) ValidateField(field eval.Field, fieldValue eval.FieldValue) error {
	if m.ExtraValidateFieldFnc != nil {
		return m.ExtraValidateFieldFnc(field, fieldValue)
	}

	return nil
}

// Event represents an event sent from the kernel
// genaccessors
// gengetter: GetContainerId
// gengetter: GetContainerId
// gengetter: GetEventService
// gengetter: GetExecFilePath
// gengetter: GetExitCode
// gengetter: GetProcessEnvp
// gengetter: GetProcessExecTime
// gengetter: GetProcessExitTime
// gengetter: GetProcessPid
// gengetter: GetProcessPpid
// gengetter: GetTimestamp
type Event struct {
	BaseEvent

	// process events
	Exec ExecEvent `field:"exec" event:"exec"` // [7.27] [Process] A process was executed or forked
	Exit ExitEvent `field:"exit" event:"exit"` // [7.38] [Process] A process was terminated

	// FIM
	CreateNewFile CreateNewFileEvent `field:"create" event:"create"` // [7.52] [File] A file was created
	RenameFile    RenameFileEvent    `field:"rename" event:"rename"` // [7.54] [File] A file was renamed
	DeleteFile    DeleteFileEvent    `field:"delete" event:"delete"` // [7.54] [File] A file was deleted
	WriteFile     WriteFileEvent     `field:"write" event:"write"`   // [7.54] [File] A file was written

	// Registries
	CreateRegistryKey   CreateRegistryKeyEvent   `field:"create_key;create" event:"create_key" `   // [7.52] [Registry] A registry key was created
	OpenRegistryKey     OpenRegistryKeyEvent     `field:"open_key;open" event:"open_key"`          // [7.52] [Registry] A registry key was opened
	SetRegistryKeyValue SetRegistryKeyValueEvent `field:"set_key_value;set" event:"set_key_value"` // [7.52] [Registry] A registry key value was set
	DeleteRegistryKey   DeleteRegistryKeyEvent   `field:"delete_key;delete" event:"delete_key"`    // [7.52] [Registry] A registry key was deleted

	ChangePermission ChangePermissionEvent `field:"change_permission" event:"change_permission" ` // [7.55] [Registry] A permission change was made
}

var eventZero = Event{BaseEvent: BaseEvent{ContainerContext: &ContainerContext{}, Os: runtime.GOOS}}

// Zero the event
func (e *Event) Zero() {
	*e = eventZero
	*e.BaseEvent.ContainerContext = containerContextZero
}

// FileEvent is the common file event type
type FileEvent struct {
	FileObject  uint64 `field:"-"`                                                                                      // handle numeric value
	PathnameStr string `field:"path,handler:ResolveFilePath,opts:length|gen_getters" op_override:"eval.WindowsPathCmp"` // SECLDoc[path] Definition:`File's path` Example:`exec.file.path == "c:\cmd.bat"` Description:`Matches the execution of the file located at c:\cmd.bat`
	BasenameStr string `field:"name,handler:ResolveFileBasename,opts:length" op_override:"eval.CaseInsensitiveCmp"`     // SECLDoc[name] Definition:`File's basename` Example:`exec.file.name == "cmd.bat"` Description:`Matches the execution of any file named cmd.bat.`
	Extension   string `field:"extension,handler:ResolveFileExtension" op_override:"eval.CaseInsensitiveCmp"`           // SECLDoc[extension] Definition:`File's extension`
}

// FimFileEvent is the common file event type
type FimFileEvent struct {
	FileObject      uint64 `field:"-"`                                                                                     // handle numeric value
	PathnameStr     string `field:"device_path,handler:ResolveFimFilePath,opts:length" op_override:"eval.WindowsPathCmp"`  // SECLDoc[device_path] Definition:`File's path` Example:`create.file.device_path == "\device\harddisk1\cmd.bat"` Description:`Matches the creation of the file located at c:\cmd.bat`
	UserPathnameStr string `field:"path,handler:ResolveFileUserPath,opts:length" op_override:"eval.WindowsPathCmp"`        // SECLDoc[path] Definition:`File's path` Example:`create.file.path == "c:\cmd.bat"` Description:`Matches the creation of the file located at c:\cmd.bat`
	BasenameStr     string `field:"name,handler:ResolveFimFileBasename,opts:length" op_override:"eval.CaseInsensitiveCmp"` // SECLDoc[name] Definition:`File's basename` Example:`create.file.name == "cmd.bat"` Description:`Matches the creation of any file named cmd.bat.`
	Extension       string `field:"extension,handler:ResolveFimFileExtension" op_override:"eval.CaseInsensitiveCmp"`       // SECLDoc[extension] Definition:`File's extension`
}

// RegistryEvent is the common registry event type
type RegistryEvent struct {
	KeyName string `field:"key_name,opts:length"`                                       // SECLDoc[key_name] Definition:`Registry's name`
	KeyPath string `field:"key_path,opts:length" op_override:"eval.CaseInsensitiveCmp"` // SECLDoc[key_path] Definition:`Registry's path`
}

// Process represents a process
type Process struct {
	PIDContext

	FileEvent FileEvent `field:"file"`

	ContainerID string `field:"container.id"` // SECLDoc[container.id] Definition:`Container ID`

	ExitTime time.Time `field:"exit_time,opts:getters_only|gen_getters"`
	ExecTime time.Time `field:"exec_time,opts:getters_only|gen_getters"`

	CreatedAt uint64 `field:"created_at,handler:ResolveProcessCreatedAt"` // SECLDoc[created_at] Definition:`Timestamp of the creation of the process`

	PPid uint32 `field:"ppid"` // SECLDoc[ppid] Definition:`Parent process ID`

	ArgsEntry *ArgsEntry `field:"-"`
	EnvsEntry *EnvsEntry `field:"-"`

	CmdLine         string `field:"cmdline,handler:ResolveProcessCmdLine,weight:200" op_override:"eval.CaseInsensitiveCmp"` // SECLDoc[cmdline] Definition:`Command line of the process` Example:`exec.cmdline == "-sV -p 22,53,110,143,4564 198.116.0-255.1-127"` Description:`Matches any process with these exact arguments.` Example:`exec.cmdline =~ "* -F * http*"` Description:`Matches any process that has the "-F" argument anywhere before an argument starting with "http".`
	CmdLineScrubbed string `field:"cmdline_scrubbed,handler:ResolveProcessCmdLineScrubbed,weight:500,opts:getters_only"`

	OwnerSidString string `field:"user_sid"`                 // SECLDoc[user_sid] Definition:`Sid of the user of the process`
	User           string `field:"user,handler:ResolveUser"` // SECLDoc[user] Definition:`User name`

	Envs []string `field:"envs,handler:ResolveProcessEnvs,weight:100"` // SECLDoc[envs] Definition:`Environment variable names of the process`
	Envp []string `field:"envp,handler:ResolveProcessEnvp,weight:100"` // SECLDoc[envp] Definition:`Environment variables of the process`                                                                                                                         // SECLDoc[envp] Definition:`Environment variables of the process`

	// cache version
	ScrubbedCmdLineResolved bool `field:"-"`
}

// ExecEvent represents a exec event
type ExecEvent struct {
	*Process
}

// PIDContext holds the process context of an kernel event
type PIDContext struct {
	Pid uint32 `field:"pid"` // SECLDoc[pid] Definition:`Process ID of the process (also called thread group ID)`
}

// NetworkDeviceContext defines a network device context
type NetworkDeviceContext struct{}

// ExtraFieldHandlers handlers not hold by any field
type ExtraFieldHandlers interface {
	BaseExtraFieldHandlers
}

// FIM

// CreateNewFileEvent defines file creation
type CreateNewFileEvent struct {
	File FimFileEvent `field:"file"` // SECLDoc[file] Definition:`File Event`
}

// RenameFileEvent defines file renaming
type RenameFileEvent struct {
	Old FimFileEvent `field:"file"`             // SECLDoc[file] Definition:`File Event`
	New FimFileEvent `field:"file.destination"` // SECLDoc[file] Definition:`File Event`
}

// DeleteFileEvent represents an unlink event
type DeleteFileEvent struct {
	File FimFileEvent `field:"file"` // SECLDoc[file] Definition:`File Event`
}

// WriteFileEvent represents a write event
type WriteFileEvent struct {
	File FimFileEvent `field:"file"` // SECLDoc[file] Definition:`File Event`
}

// Registries

// CreateRegistryKeyEvent defines registry key creation
type CreateRegistryKeyEvent struct {
	Registry RegistryEvent `field:"registry"` // SECLDoc[registry] Definition:`Registry Event`
}

// OpenRegistryKeyEvent defines registry key opening
type OpenRegistryKeyEvent struct {
	Registry RegistryEvent `field:"registry"` // SECLDoc[registry] Definition:`Registry Event`
}

// SetRegistryKeyValueEvent defines the event of setting up a value of a registry key
type SetRegistryKeyValueEvent struct {
	Registry  RegistryEvent `field:"registry"`                                   // SECLDoc[registry] Definition:`Registry Event`
	ValueName string        `field:"value_name;registry.value_name,opts:length"` // SECLDoc[value_name] Definition:`Registry's value name` SECLDoc[registry.value_name] Definition:`Registry's value name`
}

// DeleteRegistryKeyEvent defines registry key deletion
type DeleteRegistryKeyEvent struct {
	Registry RegistryEvent `field:"registry"` // SECLDoc[registry] Definition:`Registry Event`
}

// ChangePermissionEvent defines object permission change
type ChangePermissionEvent struct {
	UserName   string `field:"username"`                                    // SECLDoc[username] Definition:`Username of the permission change author`
	UserDomain string `field:"user_domain"`                                 // SECLDoc[user_domain] Definition:`Domain name of the permission change author`
	ObjectName string `field:"path"`                                        // SECLDoc[path] Definition:`Name of the object of which permission was changed`
	ObjectType string `field:"type"`                                        // SECLDoc[type] Definition:`Type of the object of which permission was changed`
	OldSd      string `field:"old_sd,handler:ResolveOldSecurityDescriptor"` // SECLDoc[old_sd] Definition:`Original Security Descriptor of the object of which permission was changed`
	NewSd      string `field:"new_sd,handler:ResolveNewSecurityDescriptor"` // SECLDoc[new_sd] Definition:`New Security Descriptor of the object of which permission was changed`
}

// SetAncestorFields force the process cache entry to be valid
func SetAncestorFields(_ *ProcessCacheEntry, _ string, _ interface{}) (bool, error) {
	return true, nil
}

// Hash returns a unique key for the entity
func (pc *ProcessCacheEntry) Hash() string {
	return strconv.Itoa(int(pc.Pid))
}

// ParentScope returns the parent entity scope
func (pc *ProcessCacheEntry) ParentScope() (eval.VariableScope, bool) {
	return pc.Ancestor, pc.Ancestor != nil
}

// GetFileField returns the FileEvent associated with a field name
func (e *Event) GetFileField(field string) (*FileEvent, error) {
	// TODO(lebauce): generate this function
	switch field {
	case "exec.file":
		if e.Exec.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exec.FileEvent, nil
	case "exit.file":
		if e.Exit.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exit.FileEvent, nil
	case "process.file":
		if e.ProcessContext == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.FileEvent, nil
	case "process.parent.file":
		if e.ProcessContext == nil || e.ProcessContext.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.Parent.FileEvent, nil
	default:
		return nil, fmt.Errorf("invalid field %s on event %s", field, e.GetEventType())
	}
}

// ValidateFileField validates that GetFileField would return a valid FileEvent
func (e *Event) ValidateFileField(field string) error {
	// TODO(lebauce): generate this function + keep in sync with GetFileField
	switch field {
	case "exec.file",
		"exit.file",
		"process.file",
		"process.parent.file":
		return nil
	default:
		return fmt.Errorf("invalid field %s on event %s", field, e.GetEventType())
	}
}
