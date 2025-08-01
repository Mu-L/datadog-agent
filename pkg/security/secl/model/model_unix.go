// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build unix

//go:generate accessors -tags unix -types-file model.go -output accessors_unix.go -field-handlers field_handlers_unix.go -doc ../../../../docs/cloud-workload-security/secl_linux.json -field-accessors-output field_accessors_unix.go

// Package model holds model related files
package model

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/google/gopacket"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/containerutils"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model/utils"
)

const (
	// FileFieldsSize is the size used by the file_t structure
	FileFieldsSize = 72
)

// NewEvent returns a new Event
func (m *Model) NewEvent() eval.Event {
	return &Event{
		BaseEvent: BaseEvent{
			ContainerContext: &ContainerContext{},
			Os:               runtime.GOOS,
		},
		CGroupContext: &CGroupContext{},
	}
}

// NewFakeEvent returns a new event using the default field handlers
func NewFakeEvent() *Event {
	return &Event{
		BaseEvent: BaseEvent{
			FieldHandlers:    &FakeFieldHandlers{},
			ContainerContext: &ContainerContext{},
			ProcessContext:   &ProcessContext{},
			Os:               runtime.GOOS,
		},
		CGroupContext: &CGroupContext{},
	}
}

// ResolveProcessCacheEntryFromPID stub implementation
func (fh *FakeFieldHandlers) ResolveProcessCacheEntryFromPID(pid uint32) *ProcessCacheEntry {
	return GetPlaceholderProcessCacheEntry(pid, pid, false)
}

// Event represents an event sent from the kernel
// genaccessors
// gengetter: GetContainerCreatedAt
// gengetter: GetContainerId
// gengetter: GetExecCmdargv
// gengetter: GetExecFilePath
// gengetter: GetExecFilePath)
// gengetter: GetExitCode
// gengetter: GetMountMountpointPath
// gengetter: GetMountRootPath
// gengetter: GetProcessEnvp
// gengetter: GetProcessExecTime
// gengetter: GetProcessExitTime
// gengetter: GetProcessForkTime
// gengetter: GetProcessGid
// gengetter: GetProcessGroup
// gengetter: GetProcessPid
// gengetter: GetProcessPpid
// gengetter: GetProcessUid
// gengetter: GetProcessUser
// gengetter: GetTimestamp
// gengetter: GetEventService
type Event struct {
	BaseEvent

	// globals
	Async bool `field:"event.async,handler:ResolveAsync"` // SECLDoc[event.async] Definition:`True if the syscall was asynchronous`

	// context
	SpanContext    SpanContext    `field:"-"`
	NetworkContext NetworkContext `field:"network" restricted_to:"dns,imds"` // [7.36] [Network] Network context
	CGroupContext  *CGroupContext `field:"cgroup"`

	// fim events
	Chmod       ChmodEvent     `field:"chmod" event:"chmod"`             // [7.27] [File] A file's permissions were changed
	Chown       ChownEvent     `field:"chown" event:"chown"`             // [7.27] [File] A file's owner was changed
	Open        OpenEvent      `field:"open" event:"open"`               // [7.27] [File] A file was opened
	Mkdir       MkdirEvent     `field:"mkdir" event:"mkdir"`             // [7.27] [File] A directory was created
	Rmdir       RmdirEvent     `field:"rmdir" event:"rmdir"`             // [7.27] [File] A directory was removed
	Rename      RenameEvent    `field:"rename" event:"rename"`           // [7.27] [File] A file/directory was renamed
	Unlink      UnlinkEvent    `field:"unlink" event:"unlink"`           // [7.27] [File] A file was deleted
	Utimes      UtimesEvent    `field:"utimes" event:"utimes"`           // [7.27] [File] Change file access/modification times
	Link        LinkEvent      `field:"link" event:"link"`               // [7.27] [File] Create a new name/alias for a file
	SetXAttr    SetXAttrEvent  `field:"setxattr" event:"setxattr"`       // [7.27] [File] Set exteneded attributes
	RemoveXAttr SetXAttrEvent  `field:"removexattr" event:"removexattr"` // [7.27] [File] Remove extended attributes
	Splice      SpliceEvent    `field:"splice" event:"splice"`           // [7.36] [File] A splice command was executed
	Mount       MountEvent     `field:"mount" event:"mount"`             // [7.42] [File] [Experimental] A filesystem was mounted
	Chdir       ChdirEvent     `field:"chdir" event:"chdir"`             // [7.52] [File] [Experimental] A process changed the current directory
	Setrlimit   SetrlimitEvent `field:"setrlimit" event:"setrlimit"`     // [7.68] [Process] A setrlimit command was executed

	// process events
	Exec          ExecEvent          `field:"exec" event:"exec"`     // [7.27] [Process] A process was executed (does not trigger on fork syscalls).
	SetUID        SetuidEvent        `field:"setuid" event:"setuid"` // [7.27] [Process] A process changed its effective uid
	SetGID        SetgidEvent        `field:"setgid" event:"setgid"` // [7.27] [Process] A process changed its effective gid
	Capset        CapsetEvent        `field:"capset" event:"capset"` // [7.27] [Process] A process changed its capacity set
	Signal        SignalEvent        `field:"signal" event:"signal"` // [7.35] [Process] A signal was sent
	Exit          ExitEvent          `field:"exit" event:"exit"`     // [7.38] [Process] A process was terminated
	Syscalls      SyscallsEvent      `field:"-"`
	LoginUIDWrite LoginUIDWriteEvent `field:"-"`

	// network syscalls
	Bind       BindEvent       `field:"bind" event:"bind"`             // [7.37] [Network] A bind was executed
	Connect    ConnectEvent    `field:"connect" event:"connect"`       // [7.60] [Network] A connect was executed
	Accept     AcceptEvent     `field:"accept" event:"accept"`         // [7.63] [Network] An accept was executed
	SetSockOpt SetSockOptEvent `field:"setsockopt" event:"setsockopt"` // [7.68] [Network] A setsockopt was executed

	// kernel events
	SELinux      SELinuxEvent      `field:"selinux" event:"selinux"`             // [7.30] [Kernel] An SELinux operation was run
	BPF          BPFEvent          `field:"bpf" event:"bpf"`                     // [7.33] [Kernel] A BPF command was executed
	PTrace       PTraceEvent       `field:"ptrace" event:"ptrace"`               // [7.35] [Kernel] A ptrace command was executed
	MMap         MMapEvent         `field:"mmap" event:"mmap"`                   // [7.35] [Kernel] A mmap command was executed
	MProtect     MProtectEvent     `field:"mprotect" event:"mprotect"`           // [7.35] [Kernel] A mprotect command was executed
	LoadModule   LoadModuleEvent   `field:"load_module" event:"load_module"`     // [7.35] [Kernel] A new kernel module was loaded
	UnloadModule UnloadModuleEvent `field:"unload_module" event:"unload_module"` // [7.35] [Kernel] A kernel module was deleted
	SysCtl       SysCtlEvent       `field:"sysctl" event:"sysctl"`               // [7.65] [Kernel] A sysctl parameter was read or modified
	CgroupWrite  CgroupWriteEvent  `field:"cgroup_write" event:"cgroup_write"`   // [7.68] [Kernel] A process migrated another process to a cgroup

	// network events
	DNS                DNSEvent                `field:"dns" event:"dns"`                                   // [7.36] [Network] A DNS request was sent
	IMDS               IMDSEvent               `field:"imds" event:"imds"`                                 // [7.55] [Network] An IMDS event was captured
	RawPacket          RawPacketEvent          `field:"packet" event:"packet"`                             // [7.60] [Network] A raw network packet was captured
	NetworkFlowMonitor NetworkFlowMonitorEvent `field:"network_flow_monitor" event:"network_flow_monitor"` // [7.63] [Network] A network monitor event was sent

	// on-demand events
	OnDemand OnDemandEvent `field:"ondemand" event:"ondemand"`

	// internal usage
	Umount           UmountEvent           `field:"-"`
	InvalidateDentry InvalidateDentryEvent `field:"-"`
	ArgsEnvs         ArgsEnvsEvent         `field:"-"`
	MountReleased    MountReleasedEvent    `field:"-"`
	CgroupTracing    CgroupTracingEvent    `field:"-"`
	NetDevice        NetDeviceEvent        `field:"-"`
	VethPair         VethPairEvent         `field:"-"`
	UnshareMountNS   UnshareMountNSEvent   `field:"-"`
}

var eventZero = Event{CGroupContext: &CGroupContext{}, BaseEvent: BaseEvent{ContainerContext: &ContainerContext{}, Os: runtime.GOOS}}
var cgroupContextZero CGroupContext

// Zero the event
func (e *Event) Zero() {
	*e = eventZero
	*e.BaseEvent.ContainerContext = containerContextZero
	*e.CGroupContext = cgroupContextZero
}

// CGroupContext holds the cgroup context of an event
type CGroupContext struct {
	Releasable
	CGroupID      containerutils.CGroupID    `field:"id,handler:ResolveCGroupID"` // SECLDoc[id] Definition:`ID of the cgroup`
	CGroupFlags   containerutils.CGroupFlags `field:"-"`
	CGroupManager string                     `field:"manager,handler:ResolveCGroupManager"` // SECLDoc[manager] Definition:`[Experimental] Lifecycle manager of the cgroup`
	CGroupFile    PathKey                    `field:"file"`
	CGroupVersion int                        `field:"version,handler:ResolveCGroupVersion"` // SECLDoc[version] Definition:`[Experimental] Version of the cgroup API`
}

// Merge two cgroup context
func (cg *CGroupContext) Merge(cg2 *CGroupContext) {
	if cg.CGroupID == "" {
		cg.CGroupID = cg2.CGroupID
	}
	if cg.CGroupFlags == 0 {
		cg.CGroupFlags = cg2.CGroupFlags
	}
	if cg.CGroupFile.Inode == 0 {
		cg.CGroupFile.Inode = cg2.CGroupFile.Inode
	}
	if cg.CGroupFile.MountID == 0 {
		cg.CGroupFile.MountID = cg2.CGroupFile.MountID
	}
}

// IsContainer returns whether a cgroup maps to a container
func (cg *CGroupContext) IsContainer() bool {
	return cg.CGroupFlags.IsContainer()
}

// Hash returns a unique key for the entity
func (cg *CGroupContext) Hash() string {
	return string(cg.CGroupID)
}

// ParentScope returns the parent entity scope
func (cg *CGroupContext) ParentScope() (eval.VariableScope, bool) {
	return nil, false
}

// SyscallEvent contains common fields for all the event
type SyscallEvent struct {
	Retval int64 `field:"retval"` // SECLDoc[retval] Definition:`Return value of the syscall` Constants:`Error constants`
}

// SyscallContext contains syscall context
type SyscallContext struct {
	ID uint32 `field:"-"`

	StrArg1 string `field:"syscall.str1,handler:ResolveSyscallCtxArgsStr1,weight:900,opts:getters_only|skip_ad"`
	StrArg2 string `field:"syscall.str2,handler:ResolveSyscallCtxArgsStr2,weight:900,opts:getters_only|skip_ad"`
	StrArg3 string `field:"syscall.str3,handler:ResolveSyscallCtxArgsStr3,weight:900,opts:getters_only|skip_ad"`

	IntArg1 int64 `field:"syscall.int1,handler:ResolveSyscallCtxArgsInt1,weight:900,opts:getters_only|skip_ad"`
	IntArg2 int64 `field:"syscall.int2,handler:ResolveSyscallCtxArgsInt2,weight:900,opts:getters_only|skip_ad"`
	IntArg3 int64 `field:"syscall.int3,handler:ResolveSyscallCtxArgsInt3,weight:900,opts:getters_only|skip_ad"`

	Resolved bool `field:"-"`
}

// ChmodEvent represents a chmod event
type ChmodEvent struct {
	SyscallEvent
	SyscallContext
	File FileEvent `field:"file"`
	Mode uint32    `field:"file.destination.mode; file.destination.rights"` // SECLDoc[file.destination.mode] Definition:`New mode of the chmod-ed file` Constants:`File mode constants` SECLDoc[file.destination.rights] Definition:`New rights of the chmod-ed file` Constants:`File mode constants`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:chmod.syscall.str1"` // SECLDoc[syscall.path] Definition:`path argument of the syscall`
	SyscallMode int64  `field:"syscall.mode,ref:chmod.syscall.int2"` // SECLDoc[syscall.mode] Definition:`mode argument of the syscall`
}

// ChownEvent represents a chown event
type ChownEvent struct {
	SyscallEvent
	SyscallContext
	File  FileEvent `field:"file"`
	UID   int64     `field:"file.destination.uid"`                           // SECLDoc[file.destination.uid] Definition:`New UID of the chown-ed file's owner`
	User  string    `field:"file.destination.user,handler:ResolveChownUID"`  // SECLDoc[file.destination.user] Definition:`New user of the chown-ed file's owner`
	GID   int64     `field:"file.destination.gid"`                           // SECLDoc[file.destination.gid] Definition:`New GID of the chown-ed file's owner`
	Group string    `field:"file.destination.group,handler:ResolveChownGID"` // SECLDoc[file.destination.group] Definition:`New group of the chown-ed file's owner`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:chown.syscall.str1"` // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallUID  int64  `field:"syscall.uid,ref:chown.syscall.int2"`  // SECLDoc[syscall.uid] Definition:`UID argument of the syscall`
	SyscallGID  int64  `field:"syscall.gid,ref:chown.syscall.int3"`  // SECLDoc[syscall.gid] Definition:`GID argument of the syscall`
}

// SetuidEvent represents a setuid event
type SetuidEvent struct {
	UID    uint32 `field:"uid"`                                // SECLDoc[uid] Definition:`New UID of the process`
	User   string `field:"user,handler:ResolveSetuidUser"`     // SECLDoc[user] Definition:`New user of the process`
	EUID   uint32 `field:"euid"`                               // SECLDoc[euid] Definition:`New effective UID of the process`
	EUser  string `field:"euser,handler:ResolveSetuidEUser"`   // SECLDoc[euser] Definition:`New effective user of the process`
	FSUID  uint32 `field:"fsuid"`                              // SECLDoc[fsuid] Definition:`New FileSystem UID of the process`
	FSUser string `field:"fsuser,handler:ResolveSetuidFSUser"` // SECLDoc[fsuser] Definition:`New FileSystem user of the process`
}

// SetgidEvent represents a setgid event
type SetgidEvent struct {
	GID     uint32 `field:"gid"`                                  // SECLDoc[gid] Definition:`New GID of the process`
	Group   string `field:"group,handler:ResolveSetgidGroup"`     // SECLDoc[group] Definition:`New group of the process`
	EGID    uint32 `field:"egid"`                                 // SECLDoc[egid] Definition:`New effective GID of the process`
	EGroup  string `field:"egroup,handler:ResolveSetgidEGroup"`   // SECLDoc[egroup] Definition:`New effective group of the process`
	FSGID   uint32 `field:"fsgid"`                                // SECLDoc[fsgid] Definition:`New FileSystem GID of the process`
	FSGroup string `field:"fsgroup,handler:ResolveSetgidFSGroup"` // SECLDoc[fsgroup] Definition:`New FileSystem group of the process`
}

// CapsetEvent represents a capset event
type CapsetEvent struct {
	CapEffective uint64 `field:"cap_effective"` // SECLDoc[cap_effective] Definition:`Effective capability set of the process` Constants:`Kernel Capability constants`
	CapPermitted uint64 `field:"cap_permitted"` // SECLDoc[cap_permitted] Definition:`Permitted capability set of the process` Constants:`Kernel Capability constants`
}

// Credentials represents the kernel credentials of a process
type Credentials struct {
	UID   uint32 `field:"uid"`   // SECLDoc[uid] Definition:`UID of the process`
	GID   uint32 `field:"gid"`   // SECLDoc[gid] Definition:`GID of the process`
	User  string `field:"user"`  // SECLDoc[user] Definition:`User of the process` Example:`process.user == "root"` Description:`Constrain an event to be triggered by a process running as the root user.`
	Group string `field:"group"` // SECLDoc[group] Definition:`Group of the process`

	EUID   uint32 `field:"euid"`   // SECLDoc[euid] Definition:`Effective UID of the process`
	EGID   uint32 `field:"egid"`   // SECLDoc[egid] Definition:`Effective GID of the process`
	EUser  string `field:"euser"`  // SECLDoc[euser] Definition:`Effective user of the process`
	EGroup string `field:"egroup"` // SECLDoc[egroup] Definition:`Effective group of the process`

	FSUID   uint32 `field:"fsuid"`   // SECLDoc[fsuid] Definition:`FileSystem-uid of the process`
	FSGID   uint32 `field:"fsgid"`   // SECLDoc[fsgid] Definition:`FileSystem-gid of the process`
	FSUser  string `field:"fsuser"`  // SECLDoc[fsuser] Definition:`FileSystem-user of the process`
	FSGroup string `field:"fsgroup"` // SECLDoc[fsgroup] Definition:`FileSystem-group of the process`

	AUID uint32 `field:"auid"` // SECLDoc[auid] Definition:`Login UID of the process`

	CapEffective uint64 `field:"cap_effective"` // SECLDoc[cap_effective] Definition:`Effective capability set of the process` Constants:`Kernel Capability constants`
	CapPermitted uint64 `field:"cap_permitted"` // SECLDoc[cap_permitted] Definition:`Permitted capability set of the process` Constants:`Kernel Capability constants`
}

// LinuxBinprm contains content from the linux_binprm struct, which holds the arguments used for loading binaries
type LinuxBinprm struct {
	FileEvent FileEvent `field:"file"`
}

// SetInterpreterFields set the proper field so that this will be seen as a valid interpreter, see HasInterpreter
func SetInterpreterFields(bprm *LinuxBinprm, subField string, _ interface{}) (bool, error) {
	// set a fake inode so that the interpreter becomes valid
	if bprm.FileEvent.Inode == 0 && subField != "file.inode" {
		bprm.FileEvent.Inode = fakeInodeMSW
	}
	return true, nil
}

// Process represents a process
type Process struct {
	PIDContext

	FileEvent FileEvent `field:"file,check:IsNotKworker"`

	CGroup      CGroupContext              `field:"cgroup"`                                         // SECLDoc[cgroup] Definition:`CGroup`
	ContainerID containerutils.ContainerID `field:"container.id,handler:ResolveProcessContainerID"` // SECLDoc[container.id] Definition:`Container ID`

	SpanID  uint64        `field:"-"`
	TraceID utils.TraceID `field:"-"`

	TTYName     string      `field:"tty_name"`                                                          // SECLDoc[tty_name] Definition:`Name of the TTY associated with the process`
	Comm        string      `field:"comm"`                                                              // SECLDoc[comm] Definition:`Comm attribute of the process`
	LinuxBinprm LinuxBinprm `field:"interpreter,check:HasInterpreter,set_handler:SetInterpreterFields"` // Script interpreter as identified by the shebang

	// pid_cache_t
	ForkTime time.Time `field:"fork_time,opts:getters_only"`
	ExitTime time.Time `field:"exit_time,opts:getters_only"`
	ExecTime time.Time `field:"exec_time,opts:getters_only"`

	// TODO: merge with ExecTime
	CreatedAt uint64 `field:"created_at,handler:ResolveProcessCreatedAt"` // SECLDoc[created_at] Definition:`Timestamp of the creation of the process`

	Cookie uint64 `field:"-"`
	PPid   uint32 `field:"ppid"` // SECLDoc[ppid] Definition:`Parent process ID`

	// credentials_t section of pid_cache_t
	Credentials

	UserSession UserSessionContext `field:"user_session"` // SECLDoc[user_session] Definition:`User Session context of this process`

	AWSSecurityCredentials []AWSSecurityCredentials `field:"-"`

	ArgsID uint64 `field:"-"`
	EnvsID uint64 `field:"-"`

	ArgsEntry *ArgsEntry `field:"-"`
	EnvsEntry *EnvsEntry `field:"-"`

	// defined to generate accessors, ArgsTruncated and EnvsTruncated are used during by unmarshaller
	Argv0         string   `field:"argv0,handler:ResolveProcessArgv0,weight:100"`                                                                                                                                                                            // SECLDoc[argv0] Definition:`First argument of the process`
	Args          string   `field:"args,handler:ResolveProcessArgs,weight:500,opts:skip_ad"`                                                                                                                                                                 // SECLDoc[args] Definition:`Arguments of the process (as a string, excluding argv0)` Example:`exec.args == "-sV -p 22,53,110,143,4564 198.116.0-255.1-127"` Description:`Matches any process with these exact arguments.` Example:`exec.args =~ "* -F * http*"` Description:`Matches any process that has the "-F" argument anywhere before an argument starting with "http".`
	Argv          []string `field:"argv,handler:ResolveProcessArgv,weight:500; cmdargv,handler:ResolveProcessCmdArgv,opts:getters_only; args_flags,handler:ResolveProcessArgsFlags,opts:helper; args_options,handler:ResolveProcessArgsOptions,opts:helper"` // SECLDoc[argv] Definition:`Arguments of the process (as an array, excluding argv0)` Example:`exec.argv in ["127.0.0.1"]` Description:`Matches any process that has this IP address as one of its arguments.` SECLDoc[args_flags] Definition:`Flags in the process arguments` Example:`exec.args_flags in ["s"] && exec.args_flags in ["V"]` Description:`Matches any process with both "-s" and "-V" flags in its arguments. Also matches "-sV".` SECLDoc[args_options] Definition:`Argument of the process as options` Example:`exec.args_options in ["p=0-1024"]` Description:`Matches any process that has either "-p 0-1024" or "--p=0-1024" in its arguments.`
	ArgsTruncated bool     `field:"args_truncated,handler:ResolveProcessArgsTruncated"`                                                                                                                                                                      // SECLDoc[args_truncated] Definition:`Indicator of arguments truncation`
	Envs          []string `field:"envs,handler:ResolveProcessEnvs,weight:100"`                                                                                                                                                                              // SECLDoc[envs] Definition:`Environment variable names of the process`
	Envp          []string `field:"envp,handler:ResolveProcessEnvp,weight:100"`                                                                                                                                                                              // SECLDoc[envp] Definition:`Environment variables of the process`
	EnvsTruncated bool     `field:"envs_truncated,handler:ResolveProcessEnvsTruncated"`                                                                                                                                                                      // SECLDoc[envs_truncated] Definition:`Indicator of environment variables truncation`

	ArgsScrubbed string   `field:"args_scrubbed,handler:ResolveProcessArgsScrubbed,opts:getters_only"`
	ArgvScrubbed []string `field:"argv_scrubbed,handler:ResolveProcessArgvScrubbed,opts:getters_only"`

	// symlink to the process binary
	SymlinkPathnameStr [MaxSymlinks]string `field:"-"`
	SymlinkBasenameStr string              `field:"-"`

	// cache version
	ScrubbedArgvResolved bool `field:"-"`

	// IsThread is the negation of IsExec and should be manipulated directly
	IsThread        bool `field:"is_thread,handler:ResolveProcessIsThread"` // SECLDoc[is_thread] Definition:`Indicates whether the process is considered a thread (that is, a child process that hasn't executed another program)`
	IsExec          bool `field:"is_exec"`                                  // SECLDoc[is_exec] Definition:`Indicates whether the process entry is from a new binary execution`
	IsExecExec      bool `field:"-"`                                        // Indicates whether the process is an exec following another exec
	IsParentMissing bool `field:"-"`                                        // Indicates the direct parent is missing

	Source uint64 `field:"-"`

	// lineage
	hasValidLineage *bool `field:"-"`
	lineageError    error `field:"-"`
}

// SetAncestorFields force the process cache entry to be valid
func SetAncestorFields(pce *ProcessCacheEntry, subField string, _ interface{}) (bool, error) {
	if subField != "is_kworker" {
		pce.IsKworker = false
	}
	return true, nil
}

// Hash returns a unique key for the entity
func (pc *ProcessCacheEntry) Hash() string {
	return fmt.Sprintf("%d/%s", pc.Pid, pc.Comm)
}

// ParentScope returns the parent entity scope
func (pc *ProcessCacheEntry) ParentScope() (eval.VariableScope, bool) {
	return pc.Ancestor, pc.Ancestor != nil
}

// ExecEvent represents a exec event
type ExecEvent struct {
	SyscallContext
	*Process
	FileMetadata FileMetadata `field:"file.metadata"`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:exec.syscall.str1"` // SECLDoc[syscall.path] Definition:`path argument of the syscall`
}

// FileFields holds the information required to identify a file
type FileFields struct {
	UID   uint32 `field:"uid"`                                           // SECLDoc[uid] Definition:`UID of the file's owner`
	User  string `field:"user,handler:ResolveFileFieldsUser"`            // SECLDoc[user] Definition:`User of the file's owner`
	GID   uint32 `field:"gid"`                                           // SECLDoc[gid] Definition:`GID of the file's owner`
	Group string `field:"group,handler:ResolveFileFieldsGroup"`          // SECLDoc[group] Definition:`Group of the file's owner`
	Mode  uint16 `field:"mode;rights,handler:ResolveRights,opts:helper"` // SECLDoc[mode] Definition:`Mode of the file` Constants:`Inode mode constants` SECLDoc[rights] Definition:`Rights of the file` Constants:`File mode constants`
	CTime uint64 `field:"change_time"`                                   // SECLDoc[change_time] Definition:`Change time (ctime) of the file`
	MTime uint64 `field:"modification_time"`                             // SECLDoc[modification_time] Definition:`Modification time (mtime) of the file`

	PathKey
	Device uint32 `field:"-"`

	InUpperLayer bool `field:"in_upper_layer,handler:ResolveFileFieldsInUpperLayer"` // SECLDoc[in_upper_layer] Definition:`Indicator of the file layer, for example, in an OverlayFS`

	NLink uint32 `field:"-"`
	Flags int32  `field:"-"`
}

// FileEvent is the common file event type
type FileEvent struct {
	FileFields

	PathnameStr string `field:"path,handler:ResolveFilePath,opts:length" op_override:"ProcessSymlinkPathname"`     // SECLDoc[path] Definition:`File's path` Example:`exec.file.path == "/usr/bin/apt"` Description:`Matches the execution of the file located at /usr/bin/apt` Example:`open.file.path == "/etc/passwd"` Description:`Matches any process opening the /etc/passwd file.`
	BasenameStr string `field:"name,handler:ResolveFileBasename,opts:length" op_override:"ProcessSymlinkBasename"` // SECLDoc[name] Definition:`File's basename` Example:`exec.file.name == "apt"` Description:`Matches the execution of any file named apt.`
	Filesystem  string `field:"filesystem,handler:ResolveFileFilesystem"`                                          // SECLDoc[filesystem] Definition:`File's filesystem`
	Extension   string `field:"extension,handler:ResolveFileExtension"`                                            // SECLDoc[extension] Definition:`File's extension`

	MountPath               string `field:"-"`
	MountSource             uint32 `field:"-"`
	MountOrigin             uint32 `field:"-"`
	MountVisible            bool   `field:"mount_visible"`  // SECLDoc[mount_visible] Definition:`Indicates whether the file's mount is visible in the VFS`
	MountDetached           bool   `field:"mount_detached"` // SECLDoc[mount_detached] Definition:`Indicates whether the file's mount is detached from the VFS`
	MountVisibilityResolved bool   `field:"-"`

	PathResolutionError error `field:"-"`

	PkgName       string `field:"package.name,handler:ResolvePackageName"`                    // SECLDoc[package.name] Definition:`[Experimental] Name of the package that provided this file`
	PkgVersion    string `field:"package.version,handler:ResolvePackageVersion"`              // SECLDoc[package.version] Definition:`[Experimental] Full version of the package that provided this file`
	PkgSrcVersion string `field:"package.source_version,handler:ResolvePackageSourceVersion"` // SECLDoc[package.source_version] Definition:`[Experimental] Full version of the source package of the package that provided this file`

	HashState HashState `field:"-"`
	Hashes    []string  `field:"hashes,handler:ResolveHashesFromEvent,opts:skip_ad,weight:999"` // SECLDoc[hashes] Definition:`[Experimental] List of cryptographic hashes computed for this file`

	// used to mark as already resolved, can be used in case of empty path
	IsPathnameStrResolved bool `field:"-"`
	IsBasenameStrResolved bool `field:"-"`
}

// InvalidateDentryEvent defines a invalidate dentry event
type InvalidateDentryEvent struct {
	Inode   uint64
	MountID uint32
}

// MountReleasedEvent defines a mount released event
type MountReleasedEvent struct {
	MountID uint32
}

// LinkEvent represents a link event
type LinkEvent struct {
	SyscallEvent
	SyscallContext
	Source FileEvent `field:"file"`
	Target FileEvent `field:"file.destination"`

	// Syscall context aliases
	SyscallPath            string `field:"syscall.path,ref:link.syscall.str1"`             // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallDestinationPath string `field:"syscall.destination.path,ref:link.syscall.str2"` // SECLDoc[syscall.destination.path] Definition:`Destination path argument of the syscall`
}

// MkdirEvent represents a mkdir event
type MkdirEvent struct {
	SyscallEvent
	SyscallContext
	File FileEvent `field:"file"`
	Mode uint32    `field:"file.destination.mode; file.destination.rights"` // SECLDoc[file.destination.mode] Definition:`Mode of the new directory` Constants:`File mode constants` SECLDoc[file.destination.rights] Definition:`Rights of the new directory` Constants:`File mode constants`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:mkdir.syscall.str1"` // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallMode uint32 `field:"syscall.mode,ref:mkdir.syscall.int2"` // SECLDoc[syscall.mode] Definition:`Mode of the new directory`
}

// ArgsEnvsEvent defines a args/envs event
type ArgsEnvsEvent struct {
	ArgsEnvs
}

// Mount represents a mountpoint (used by MountEvent, FsmountEvent and UnshareMountNSEvent)
type Mount struct {
	MountID        uint32  `field:"-"`
	Device         uint32  `field:"-"`
	ParentPathKey  PathKey `field:"-"`
	RootPathKey    PathKey `field:"-"`
	BindSrcMountID uint32  `field:"-"`
	FSType         string  `field:"fs_type"` // SECLDoc[fs_type] Definition:`Type of the mounted file system`
	MountPointStr  string  `field:"-"`
	RootStr        string  `field:"-"`
	Path           string  `field:"-"`
	Origin         uint32  `field:"-"`
	Detached       bool    `field:"detached"` // SECLDoc[detached] Definition:`Mount is detached from the VFS`
	Visible        bool    `field:"visible"`  // SECLDoc[visible] Definition:`Mount is not visible in the VFS`
}

// MountEvent represents a mount event
type MountEvent struct {
	SyscallEvent
	SyscallContext
	Mount
	MountPointPath                 string `field:"mountpoint.path,handler:ResolveMountPointPath"` // SECLDoc[mountpoint.path] Definition:`Path of the mount point`
	MountSourcePath                string `field:"source.path,handler:ResolveMountSourcePath"`    // SECLDoc[source.path] Definition:`Source path of a bind mount`
	MountRootPath                  string `field:"root.path,handler:ResolveMountRootPath"`        // SECLDoc[root.path] Definition:`Root path of the mount`
	MountPointPathResolutionError  error  `field:"-"`
	MountSourcePathResolutionError error  `field:"-"`
	MountRootPathResolutionError   error  `field:"-"`

	// Syscall context aliases
	SyscallSourcePath     string `field:"syscall.source.path,ref:mount.syscall.str1"`     // SECLDoc[syscall.source.path] Definition:`Source path argument of the syscall`
	SyscallMountpointPath string `field:"syscall.mountpoint.path,ref:mount.syscall.str2"` // SECLDoc[syscall.mountpoint.path] Definition:`Mount point path argument of the syscall`
	SyscallFSType         string `field:"syscall.fs_type,ref:mount.syscall.str3"`         // SECLDoc[syscall.fs_type] Definition:`File system type argument of the syscall`
}

// UnshareMountNSEvent represents a mount cloned from a newly created mount namespace
type UnshareMountNSEvent struct {
	Mount
}

// ChdirEvent represents a chdir event
type ChdirEvent struct {
	SyscallEvent
	SyscallContext
	File FileEvent `field:"file"`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:chdir.syscall.str1"` // SECLDoc[syscall.path] Definition:`path argument of the syscall`
}

// OpenEvent represents an open event
type OpenEvent struct {
	SyscallEvent
	SyscallContext
	File  FileEvent `field:"file"`
	Flags uint32    `field:"flags"`                 // SECLDoc[flags] Definition:`Flags used when opening the file` Constants:`Open flags`
	Mode  uint32    `field:"file.destination.mode"` // SECLDoc[file.destination.mode] Definition:`Mode of the created file` Constants:`File mode constants`

	// Syscall context aliases
	SyscallPath  string `field:"syscall.path,ref:open.syscall.str1"`  // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallFlags uint32 `field:"syscall.flags,ref:open.syscall.int2"` // SECLDoc[syscall.flags] Definition:`Flags argument of the syscall`
	SyscallMode  uint32 `field:"syscall.mode,ref:open.syscall.int3"`  // SECLDoc[syscall.mode] Definition:`Mode argument of the syscall`
}

// SELinuxEvent represents a selinux event
type SELinuxEvent struct {
	File            FileEvent        `field:"-"`
	EventKind       SELinuxEventKind `field:"-"`
	BoolName        string           `field:"bool.name,handler:ResolveSELinuxBoolName"` // SECLDoc[bool.name] Definition:`SELinux boolean name`
	BoolChangeValue string           `field:"bool.state"`                               // SECLDoc[bool.state] Definition:`SELinux boolean new value`
	BoolCommitValue bool             `field:"bool_commit.state"`                        // SECLDoc[bool_commit.state] Definition:`Indicator of a SELinux boolean commit operation`
	EnforceStatus   string           `field:"enforce.status"`                           // SECLDoc[enforce.status] Definition:`SELinux enforcement status (one of "enforcing", "permissive", "disabled")`
}

// PIDContext holds the process context of a kernel event
type PIDContext struct {
	Pid       uint32 `field:"pid"` // SECLDoc[pid] Definition:`Process ID of the process (also called thread group ID)`
	Tid       uint32 `field:"tid"` // SECLDoc[tid] Definition:`Thread ID of the thread`
	NetNS     uint32 `field:"-"`
	IsKworker bool   `field:"is_kworker"` // SECLDoc[is_kworker] Definition:`Indicates whether the process is a kworker`
	ExecInode uint64 `field:"-"`          // used to track exec and event loss
	// used for ebpfless
	NSID uint64 `field:"-"`
}

// RenameEvent represents a rename event
type RenameEvent struct {
	SyscallEvent
	SyscallContext
	Old FileEvent `field:"file"`
	New FileEvent `field:"file.destination"`

	// Syscall context aliases
	SyscallPath            string `field:"syscall.path,ref:rename.syscall.str1"`             // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallDestinationPath string `field:"syscall.destination.path,ref:rename.syscall.str2"` // SECLDoc[syscall.destination.path] Definition:`Destination path argument of the syscall`
}

// RmdirEvent represents a rmdir event
type RmdirEvent struct {
	SyscallEvent
	SyscallContext
	File FileEvent `field:"file"`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:rmdir.syscall.str1"` // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
}

// SetXAttrEvent represents an extended attributes event
type SetXAttrEvent struct {
	SyscallEvent
	File      FileEvent `field:"file"`
	Namespace string    `field:"file.destination.namespace,handler:ResolveXAttrNamespace"` // SECLDoc[file.destination.namespace] Definition:`Namespace of the extended attribute`
	Name      string    `field:"file.destination.name,handler:ResolveXAttrName"`           // SECLDoc[file.destination.name] Definition:`Name of the extended attribute`

	NameRaw [200]byte `field:"-"`
}

// UnlinkEvent represents an unlink event
type UnlinkEvent struct {
	SyscallEvent
	SyscallContext
	File  FileEvent `field:"file"`
	Flags uint32    `field:"flags"` // SECLDoc[flags] Definition:`Flags of the unlink syscall` Constants:`Unlink flags`

	// Syscall context aliases
	SyscallDirFd uint64 `field:"syscall.dirfd,ref:unlink.syscall.int1"` // SECLDoc[syscall.dirfd] Definition:`Directory file descriptor argument of the syscall`
	SyscallPath  string `field:"syscall.path,ref:unlink.syscall.str2"`  // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
	SyscallFlags uint64 `field:"syscall.flags,ref:unlink.syscall.int3"` // SECLDoc[syscall.flags] Definition:`Flags argument of the syscall`
}

// UmountEvent represents an umount event
type UmountEvent struct {
	SyscallEvent
	MountID uint32
}

// UtimesEvent represents a utime event
type UtimesEvent struct {
	SyscallEvent
	SyscallContext
	File  FileEvent `field:"file"`
	Atime time.Time `field:"-"`
	Mtime time.Time `field:"-"`

	// Syscall context aliases
	SyscallPath string `field:"syscall.path,ref:utimes.syscall.str1"` // SECLDoc[syscall.path] Definition:`Path argument of the syscall`
}

// BPFEvent represents a BPF event
type BPFEvent struct {
	SyscallEvent

	Map     BPFMap     `field:"map"`  // eBPF map involved in the BPF command
	Program BPFProgram `field:"prog"` // eBPF program involved in the BPF command
	Cmd     uint32     `field:"cmd"`  // SECLDoc[cmd] Definition:`BPF command name` Constants:`BPF commands`
}

// BPFMap represents a BPF map
type BPFMap struct {
	ID   uint32 `field:"-"`    // ID of the eBPF map
	Type uint32 `field:"type"` // SECLDoc[type] Definition:`Type of the eBPF map` Constants:`BPF map types`
	Name string `field:"name"` // SECLDoc[name] Definition:`Name of the eBPF map (added in 7.35)`
}

// BPFProgram represents a BPF program
type BPFProgram struct {
	ID         uint32   `field:"-"`           // ID of the eBPF program
	Type       uint32   `field:"type"`        // SECLDoc[type] Definition:`Type of the eBPF program` Constants:`BPF program types`
	AttachType uint32   `field:"attach_type"` // SECLDoc[attach_type] Definition:`Attach type of the eBPF program` Constants:`BPF attach types`
	Helpers    []uint32 `field:"helpers"`     // SECLDoc[helpers] Definition:`eBPF helpers used by the eBPF program (added in 7.35)` Constants:`BPF helper functions`
	Name       string   `field:"name"`        // SECLDoc[name] Definition:`Name of the eBPF program (added in 7.35)`
	Tag        string   `field:"tag"`         // SECLDoc[tag] Definition:`Hash (sha1) of the eBPF program (added in 7.35)`
}

// PTraceEvent represents a ptrace event
type PTraceEvent struct {
	SyscallEvent

	Request uint32          `field:"request"` // SECLDoc[request] Definition:`ptrace request` Constants:`Ptrace constants`
	PID     uint32          `field:"-"`
	NSPID   uint32          `field:"-"`
	Address uint64          `field:"-"`
	Tracee  *ProcessContext `field:"tracee"` // process context of the tracee
}

// MMapEvent represents a mmap event
type MMapEvent struct {
	SyscallEvent

	File       FileEvent `field:"file"`
	Addr       uint64    `field:"-"`
	Offset     uint64    `field:"-"`
	Len        uint64    `field:"-"`
	Protection uint64    `field:"protection"` // SECLDoc[protection] Definition:`memory segment protection` Constants:`Protection constants`
	Flags      uint64    `field:"flags"`      // SECLDoc[flags] Definition:`memory segment flags` Constants:`MMap flags`
}

// MProtectEvent represents a mprotect event
type MProtectEvent struct {
	SyscallEvent

	VMStart       uint64 `field:"-"`
	VMEnd         uint64 `field:"-"`
	VMProtection  int    `field:"vm_protection"`  // SECLDoc[vm_protection] Definition:`initial memory segment protection` Constants:`Virtual Memory flags`
	ReqProtection int    `field:"req_protection"` // SECLDoc[req_protection] Definition:`new memory segment protection` Constants:`Virtual Memory flags`
}

// LoadModuleEvent represents a load_module event
type LoadModuleEvent struct {
	SyscallEvent

	File             FileEvent `field:"file"`                           // Path to the kernel module file
	LoadedFromMemory bool      `field:"loaded_from_memory"`             // SECLDoc[loaded_from_memory] Definition:`Indicates if the kernel module was loaded from memory`
	Name             string    `field:"name"`                           // SECLDoc[name] Definition:`Name of the new kernel module`
	Args             string    `field:"args,handler:ResolveModuleArgs"` // SECLDoc[args] Definition:`Parameters (as a string) of the new kernel module`
	Argv             []string  `field:"argv,handler:ResolveModuleArgv"` // SECLDoc[argv] Definition:`Parameters (as an array) of the new kernel module`
	ArgsTruncated    bool      `field:"args_truncated"`                 // SECLDoc[args_truncated] Definition:`Indicates if the arguments were truncated or not`
}

// UnloadModuleEvent represents an unload_module event
type UnloadModuleEvent struct {
	SyscallEvent

	Name string `field:"name"` // SECLDoc[name] Definition:`Name of the kernel module that was deleted`
}

// SignalEvent represents a signal event
type SignalEvent struct {
	SyscallEvent

	Type   uint32          `field:"type"`   // SECLDoc[type] Definition:`Signal type (ex: SIGHUP, SIGINT, SIGQUIT, etc)` Constants:`Signal constants`
	PID    uint32          `field:"pid"`    // SECLDoc[pid] Definition:`Target PID`
	Target *ProcessContext `field:"target"` // Target process context
}

// SpliceEvent represents a splice event
type SpliceEvent struct {
	SyscallEvent

	File          FileEvent `field:"file"`            // File modified by the splice syscall
	PipeEntryFlag uint32    `field:"pipe_entry_flag"` // SECLDoc[pipe_entry_flag] Definition:`Entry flag of the "fd_out" pipe passed to the splice syscall` Constants:`Pipe buffer flags`
	PipeExitFlag  uint32    `field:"pipe_exit_flag"`  // SECLDoc[pipe_exit_flag] Definition:`Exit flag of the "fd_out" pipe passed to the splice syscall` Constants:`Pipe buffer flags`
}

// CgroupTracingEvent is used to signal that a new cgroup should be traced by the activity dump manager
type CgroupTracingEvent struct {
	ContainerContext ContainerContext
	CGroupContext    CGroupContext
	Config           ActivityDumpLoadConfig
	Pid              uint32
	ConfigCookie     uint64
}

// CgroupWriteEvent is used to signal that a new cgroup was created
type CgroupWriteEvent struct {
	File        FileEvent `field:"file"` // File pointing to the cgroup
	Pid         uint32    `field:"pid"`  // SECLDoc[pid] Definition:`PID of the process added to the cgroup`
	CGroupFlags uint32    `field:"-"`    // CGroup flags
}

// ActivityDumpLoadConfig represents the load configuration of an activity dump
type ActivityDumpLoadConfig struct {
	TracedEventTypes     []EventType
	Timeout              time.Duration
	WaitListTimestampRaw uint64
	StartTimestampRaw    uint64
	EndTimestampRaw      uint64
	Rate                 uint16 // max number of events per sec
	Paused               uint32
	CGroupFlags          containerutils.CGroupFlags
}

// NetworkDeviceContext represents the network device context of a network event
type NetworkDeviceContext struct {
	NetNS   uint32 `field:"-"`
	IfIndex uint32 `field:"-"`
	IfName  string `field:"ifname,handler:ResolveNetworkDeviceIfName"` // SECLDoc[ifname] Definition:`Interface ifname`
}

// BindEvent represents a bind event
type BindEvent struct {
	SyscallEvent

	Addr       IPPortContext `field:"addr"`        // Bound address
	AddrFamily uint16        `field:"addr.family"` // SECLDoc[addr.family] Definition:`Address family`
	Protocol   uint16        `field:"protocol"`    // SECLDoc[protocol] Definition:`Socket Protocol`
}

// ConnectEvent represents a connect event
type ConnectEvent struct {
	SyscallEvent

	Addr       IPPortContext `field:"addr"`                                                       // Connection address
	Hostnames  []string      `field:"addr.hostname,handler:ResolveConnectHostnames,opts:skip_ad"` // SECLDoc[addr.hostname] Definition:`Address hostname (if available)`
	AddrFamily uint16        `field:"addr.family"`                                                // SECLDoc[addr.family] Definition:`Address family`
	Protocol   uint16        `field:"protocol"`                                                   // SECLDoc[protocol] Definition:`Socket Protocol`
}

// AcceptEvent represents an accept event
type AcceptEvent struct {
	SyscallEvent

	Addr       IPPortContext `field:"addr"`                                                      // Connection address
	Hostnames  []string      `field:"addr.hostname,handler:ResolveAcceptHostnames,opts:skip_ad"` // SECLDoc[addr.hostname] Definition:`Address hostname (if available)`
	AddrFamily uint16        `field:"addr.family"`                                               // SECLDoc[addr.family] Definition:`Address family`
}

// NetDevice represents a network device
type NetDevice struct {
	Name        string
	NetNS       uint32
	IfIndex     uint32
	PeerNetNS   uint32
	PeerIfIndex uint32
}

// NetDeviceEvent represents a network device event
type NetDeviceEvent struct {
	SyscallEvent

	Device NetDevice
}

// VethPairEvent represents a veth pair event
type VethPairEvent struct {
	SyscallEvent

	HostDevice NetDevice
	PeerDevice NetDevice
}

// SyscallsEvent represents a syscalls event
type SyscallsEvent struct {
	EventReason SyscallDriftEventReason
	Syscalls    []Syscall // 64 * 8 = 512 > 450, bytes should be enough to hold all 450 syscalls
}

// PathKey identifies an entry in the dentry cache
type PathKey struct {
	Inode   uint64 `field:"inode"`    // SECLDoc[inode] Definition:`Inode of the file`
	MountID uint32 `field:"mount_id"` // SECLDoc[mount_id] Definition:`Mount ID of the file`
	PathID  uint32 `field:"-"`
}

// OnDemandPerArgSize is the size of each argument in Data in the on-demand event
const OnDemandPerArgSize = 64

// OnDemandParsedArgsCount is the number of parsed arguments in the on-demand event
const OnDemandParsedArgsCount = 6

// OnDemandEvent identifies an on-demand event generated from on-demand probes
type OnDemandEvent struct {
	ID       uint32                                             `field:"-"`
	Name     string                                             `field:"name,handler:ResolveOnDemandName" op_override:"OnDemandNameOverrides"`
	Data     [OnDemandParsedArgsCount * OnDemandPerArgSize]byte `field:"-"`
	Arg1Str  string                                             `field:"arg1.str,handler:ResolveOnDemandArg1Str"`
	Arg1Uint uint64                                             `field:"arg1.uint,handler:ResolveOnDemandArg1Uint"`
	Arg2Str  string                                             `field:"arg2.str,handler:ResolveOnDemandArg2Str"`
	Arg2Uint uint64                                             `field:"arg2.uint,handler:ResolveOnDemandArg2Uint"`
	Arg3Str  string                                             `field:"arg3.str,handler:ResolveOnDemandArg3Str"`
	Arg3Uint uint64                                             `field:"arg3.uint,handler:ResolveOnDemandArg3Uint"`
	Arg4Str  string                                             `field:"arg4.str,handler:ResolveOnDemandArg4Str"`
	Arg4Uint uint64                                             `field:"arg4.uint,handler:ResolveOnDemandArg4Uint"`
	Arg5Str  string                                             `field:"arg5.str,handler:ResolveOnDemandArg5Str"`
	Arg5Uint uint64                                             `field:"arg5.uint,handler:ResolveOnDemandArg5Uint"`
	Arg6Str  string                                             `field:"arg6.str,handler:ResolveOnDemandArg6Str"`
	Arg6Uint uint64                                             `field:"arg6.uint,handler:ResolveOnDemandArg6Uint"`
}

// LoginUIDWriteEvent is used to propagate login UID updates to user space
type LoginUIDWriteEvent struct {
	AUID uint32 `field:"-"`
}

// SnapshottedBoundSocket represents a snapshotted bound socket
type SnapshottedBoundSocket struct {
	IP       net.IP
	Port     uint16
	Family   uint16
	Protocol uint16
}

// RawPacketEvent represents a packet event
type RawPacketEvent struct {
	NetworkContext
	TLSContext  TLSContext           `field:"tls"`                                       // SECLDoc[tls] Definition:`TLS context`
	Filter      string               `field:"filter" op_override:"PacketFilterMatching"` // SECLDoc[filter] Definition:`pcap filter expression`
	CaptureInfo gopacket.CaptureInfo `field:"-"`
	Data        []byte               `field:"-"`
}

// NetworkStats is used to record network statistics
type NetworkStats struct {
	DataSize    uint64 `field:"data_size"`    // SECLDoc[data_size] Definition:`Amount of data transmitted or received`
	PacketCount uint64 `field:"packet_count"` // SECLDoc[packet_count] Definition:`Count of network packets transmitted or received`
}

// Add the input stats to the current stats
func (ns *NetworkStats) Add(input NetworkStats) {
	ns.DataSize += input.DataSize
	ns.PacketCount += input.PacketCount
}

// FiveTuple is used to uniquely identify a flow
type FiveTuple struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	L4Protocol  uint16
}

// Flow is used to represent a network 5-tuple with statistics
type Flow struct {
	Source      IPPortContext `field:"source"`      // source of the network packet
	Destination IPPortContext `field:"destination"` // destination of the network packet
	L3Protocol  uint16        `field:"l3_protocol"` // SECLDoc[l3_protocol] Definition:`L3 protocol of the network packet` Constants:`L3 protocols`
	L4Protocol  uint16        `field:"l4_protocol"` // SECLDoc[l4_protocol] Definition:`L4 protocol of the network packet` Constants:`L4 protocols`

	Ingress NetworkStats `field:"ingress"` // SECLDoc[ingress] Definition:`Network statistics about ingress traffic`
	Egress  NetworkStats `field:"egress"`  // SECLDoc[egress] Definition:`Network statistics about egress traffic`
}

// GetFiveTuple returns the five tuple identifying the flow
func (f *Flow) GetFiveTuple() FiveTuple {
	return FiveTuple{
		Source:      f.Source.GetComparable(),
		Destination: f.Destination.GetComparable(),
		L4Protocol:  f.L4Protocol,
	}
}

// NetworkFlowMonitorEvent represents a network flow monitor event
type NetworkFlowMonitorEvent struct {
	Device     NetworkDeviceContext `field:"device"` // network device on which the network flows were captured
	FlowsCount uint64               `field:"-"`
	Flows      []Flow               `field:"flows,iterator:FlowsIterator"` // list of captured flows
}

// FlowsIterator defines an iterator of flows
type FlowsIterator struct {
	Root interface{} // not used, direct access from the event
	prev int
}

// Front returns the first element
func (it *FlowsIterator) Front(ctx *eval.Context) *Flow {
	if len(ctx.Event.(*Event).NetworkFlowMonitor.Flows) == 0 {
		return nil
	}

	front := ctx.Event.(*Event).NetworkFlowMonitor.Flows[0]
	it.prev = 0
	return &front
}

// Next returns the next element
func (it *FlowsIterator) Next(ctx *eval.Context) *Flow {
	if len(ctx.Event.(*Event).NetworkFlowMonitor.Flows) > it.prev+1 {
		it.prev++
		return &(ctx.Event.(*Event).NetworkFlowMonitor.Flows[it.prev])
	}
	return nil
}

// At returns the element at the given position
func (it *FlowsIterator) At(ctx *eval.Context, regID eval.RegisterID, pos int) *Flow {
	if entry := ctx.RegisterCache[regID]; entry != nil && entry.Pos == pos {
		return entry.Value.(*Flow)
	}

	if len(ctx.Event.(*Event).NetworkFlowMonitor.Flows) > pos {
		flow := &(ctx.Event.(*Event).NetworkFlowMonitor.Flows[pos])
		ctx.RegisterCache[regID] = &eval.RegisterCacheEntry{
			Pos:   pos,
			Value: flow,
		}
		return flow
	}

	return nil
}

// Len returns the len
func (it *FlowsIterator) Len(ctx *eval.Context) int {
	return len(ctx.Event.(*Event).NetworkFlowMonitor.Flows)
}

// SysCtlEvent is used to represent a system control parameter event
type SysCtlEvent struct {
	Action            uint32 `field:"action"`              // SECLDoc[action] Definition:`Action performed on the system control parameter` Constants:`SysCtl Actions`
	FilePosition      uint32 `field:"file_position"`       // SECLDoc[file_position] Definition:`Position in the sysctl control parameter file at which the action occurred`
	Name              string `field:"name"`                // SECLDoc[name] Definition:`Name of the system control parameter`
	NameTruncated     bool   `field:"name_truncated"`      // SECLDoc[name_truncated] Definition:`Indicates that the name field is truncated`
	OldValue          string `field:"old_value"`           // SECLDoc[old_value] Definition:`Old value of the system control parameter`
	OldValueTruncated bool   `field:"old_value_truncated"` // SECLDoc[old_value_truncated] Definition:`Indicates that the old value field is truncated`
	Value             string `field:"value"`               // SECLDoc[value] Definition:`New and/or current value for the system control parameter depending on the action type`
	ValueTruncated    bool   `field:"value_truncated"`     // SECLDoc[value_truncated] Definition:`Indicates that the value field is truncated`
}

// SetrlimitEvent represents a setrlimit event
type SetrlimitEvent struct {
	SyscallEvent
	Resource  int             `field:"resource"` // SECLDoc[resource] Definition:`Resource type being limited` Constants:`Resource limit types`
	RlimCur   uint64          `field:"rlim_cur"` // SECLDoc[rlim_cur] Definition:`Current (soft) limit value`
	RlimMax   uint64          `field:"rlim_max"` // SECLDoc[rlim_max] Definition:`Maximum (hard) limit value`
	TargetPid uint32          `field:"-"`        // Internal field, not exposed to users
	Target    *ProcessContext `field:"target"`   // SECLDoc[target] Definition:`Process context of the target process`
}

// SetSockOptEvent represents a set socket option event
type SetSockOptEvent struct {
	SyscallEvent
	SocketType         uint16 `field:"socket_type"`                                                         // SECLDoc[socket_type] Definition:`Socket type`
	SocketFamily       uint16 `field:"socket_family"`                                                       // SECLDoc[socket_family] Definition:`Socket family`
	FilterLen          uint16 `field:"filter_len"`                                                          // SECLDoc[filter_len] Definition:`Length of the filter`
	SocketProtocol     uint16 `field:"socket_protocol"`                                                     // SECLDoc[socket_protocol] Definition:`Socket protocol`
	Level              uint32 `field:"level"`                                                               // SECLDoc[level] Definition:`Socket level`
	OptName            uint32 `field:"optname"`                                                             // SECLDoc[optname] Definition:`Socket option name`
	SizeToRead         uint32 `field:"-"`                                                                   // Internal field, not exposed to users
	IsFilterTruncated  bool   `field:"is_filter_truncated"`                                                 // SECLDoc[is_filter_truncated] Definition:`Indicates that the filter is truncated`
	RawFilter          []byte `field:"-"`                                                                   // Internal field, not exposed to users
	FilterInstructions string `field:"filter_instructions,handler:ResolveSetSockOptFilterInstructions"`     // SECLDoc[filter_instructions] Definition:`Filter instructions`
	FilterHash         string `field:"filter_hash,handler:ResolveSetSockOptFilterHash:"`                    // SECLDoc[filter_hash] Definition:`Hash of the socket filter using sha256`
	UsedImmediates     []int  `field:"used_immediates,handler:ResolveSetSockOptUsedImmediates, weight:999"` // SECLDoc[used_immediates] Definition:`List of immediate values used in the filter`
}

// GetFileField returns the FileEvent associated with a field name
func (e *Event) GetFileField(field string) (*FileEvent, error) {
	// TODO(lebauce): generate this function
	switch field {
	case "cgroup_write.file":
		return &e.CgroupWrite.File, nil
	case "chdir.file":
		return &e.Chdir.File, nil
	case "chmod.file":
		return &e.Chmod.File, nil
	case "chown.file":
		return &e.Chown.File, nil
	case "exec.file":
		if e.Exec.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exec.FileEvent, nil
	case "exec.interpreter.file":
		if e.Exec.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exec.Process.LinuxBinprm.FileEvent, nil
	case "exit.file":
		if e.Exit.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exit.FileEvent, nil
	case "exit.interpreter.file":
		if e.Exit.Process == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Exit.Process.LinuxBinprm.FileEvent, nil
	case "link.file":
		return &e.Link.Source, nil
	case "load_module.file":
		return &e.LoadModule.File, nil
	case "mkdir.file":
		return &e.Mkdir.File, nil
	case "mmap.file":
		return &e.MMap.File, nil
	case "open.file":
		return &e.Open.File, nil
	case "process.file":
		if e.ProcessContext == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.FileEvent, nil
	case "process.interpreter.file":
		if e.ProcessContext == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.Process.LinuxBinprm.FileEvent, nil
	case "process.parent.file":
		if e.ProcessContext == nil || e.ProcessContext.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.Parent.FileEvent, nil
	case "process.parent.interpreter.file":
		if e.ProcessContext == nil || e.ProcessContext.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.ProcessContext.Parent.LinuxBinprm.FileEvent, nil
	case "ptrace.tracee.file":
		if e.PTrace.Tracee == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.PTrace.Tracee.FileEvent, nil
	case "ptrace.tracee.interpreter.file":
		if e.PTrace.Tracee == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.PTrace.Tracee.LinuxBinprm.FileEvent, nil
	case "ptrace.tracee.parent.file":
		if e.PTrace.Tracee == nil || e.PTrace.Tracee.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.PTrace.Tracee.Parent.FileEvent, nil
	case "ptrace.tracee.parent.interpreter.file":
		if e.PTrace.Tracee == nil || e.PTrace.Tracee.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.PTrace.Tracee.Parent.LinuxBinprm.FileEvent, nil
	case "removexattr.file":
		return &e.RemoveXAttr.File, nil
	case "rename.file":
		return &e.Rename.New, nil
	case "rmdir.file":
		return &e.Rmdir.File, nil
	case "setrlimit.target.file":
		if e.Setrlimit.Target == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Setrlimit.Target.FileEvent, nil
	case "setrlimit.target.interpreter.file":
		if e.Setrlimit.Target == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Setrlimit.Target.LinuxBinprm.FileEvent, nil
	case "setrlimit.target.parent.file":
		if e.Setrlimit.Target == nil || e.Setrlimit.Target.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Setrlimit.Target.Parent.FileEvent, nil
	case "setrlimit.target.parent.interpreter.file":
		if e.Setrlimit.Target == nil || e.Setrlimit.Target.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Setrlimit.Target.Parent.LinuxBinprm.FileEvent, nil
	case "setxattr.file":
		return &e.SetXAttr.File, nil
	case "signal.target.file":
		if e.Signal.Target == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Signal.Target.FileEvent, nil
	case "signal.target.interpreter.file":
		if e.Signal.Target == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Signal.Target.LinuxBinprm.FileEvent, nil
	case "signal.target.parent.file":
		if e.Signal.Target == nil || e.Signal.Target.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Signal.Target.Parent.FileEvent, nil
	case "signal.target.parent.interpreter.file":
		if e.Signal.Target == nil || e.Signal.Target.Parent == nil {
			return nil, fmt.Errorf("%s field is not available on this event", field)
		}
		return &e.Signal.Target.Parent.LinuxBinprm.FileEvent, nil
	case "splice.file":
		return &e.Splice.File, nil
	case "unlink.file":
		return &e.Unlink.File, nil
	case "utimes.file":
		return &e.Utimes.File, nil
	default:
		return nil, fmt.Errorf("invalid field %s on event %s", field, e.GetEventType())
	}
}

// ValidateFileField validates that GetFileField would return a valid FileEvent
func (e *Event) ValidateFileField(field string) error {
	// TODO(lebauce): generate this function + keep in sync with GetFileField
	switch field {
	case "open.file",
		"exec.file",
		"cgroup_write.file",
		"chdir.file",
		"chmod.file",
		"chown.file",
		"exec.interpreter.file",
		"exit.file",
		"exit.interpreter.file",
		"link.file",
		"load_module.file",
		"mkdir.file",
		"mmap.file",
		"process.file",
		"process.interpreter.file",
		"process.parent.file",
		"process.parent.interpreter.file",
		"ptrace.tracee.file",
		"ptrace.tracee.interpreter.file",
		"ptrace.tracee.parent.file",
		"ptrace.tracee.parent.interpreter.file",
		"removexattr.file",
		"rename.file",
		"rmdir.file",
		"setrlimit.target.file",
		"setrlimit.target.interpreter.file",
		"setrlimit.target.parent.file",
		"setrlimit.target.parent.interpreter.file",
		"setxattr.file",
		"signal.target.file",
		"signal.target.interpreter.file",
		"signal.target.parent.file",
		"signal.target.parent.interpreter.file",
		"splice.file",
		"unlink.file",
		"utimes.file":
		return nil
	default:
		return fmt.Errorf("invalid field %s on event %s", field, e.GetEventType())
	}
}
