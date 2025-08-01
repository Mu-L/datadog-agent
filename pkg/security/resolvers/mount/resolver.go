// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package mount holds mount related files
package mount

import (
	"encoding/json"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/moby/sys/mountinfo"
	"go.uber.org/atomic"

	"github.com/DataDog/datadog-go/v5/statsd"

	skernel "github.com/DataDog/datadog-agent/pkg/security/ebpf/kernel"
	"github.com/DataDog/datadog-agent/pkg/security/metrics"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup"
	cmodel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/containerutils"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/security/utils/cache"
	"github.com/DataDog/datadog-agent/pkg/security/utils/lru/simplelru"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
)

const (
	numAllowedMountIDsToResolvePerPeriod = 5
	fallbackLimiterPeriod                = time.Second
	redemptionTime                       = 2 * time.Second
)

type redemptionEntry struct {
	mount      *model.Mount
	insertedAt time.Time
}

// newMountFromMountInfo - Creates a new Mount from parsed MountInfo data
func newMountFromMountInfo(mnt *mountinfo.Info) *model.Mount {
	root := mnt.Root

	if mnt.FSType == "btrfs" {
		var subvol string
		for _, opt := range strings.Split(mnt.VFSOptions, ",") {
			name, val, ok := strings.Cut(opt, "=")
			if ok && name == "subvol" {
				subvol = val
			}
		}

		if subvol != "" {
			root = strings.TrimPrefix(root, subvol)
		}

		if root == "" {
			root = "/"
		}
	}

	if mnt.FSType == "cgroup2" && strings.HasPrefix(root, "/..") {
		cfs := utils.DefaultCGroupFS()
		root = filepath.Join(cfs.GetRootCGroupPath(), root)
	}

	// create a Mount out of the parsed MountInfo
	return &model.Mount{
		MountID: uint32(mnt.ID),
		Device:  utils.Mkdev(uint32(mnt.Major), uint32(mnt.Minor)),
		ParentPathKey: model.PathKey{
			MountID: uint32(mnt.Parent),
		},
		FSType:        mnt.FSType,
		MountPointStr: mnt.Mountpoint,
		Path:          mnt.Mountpoint,
		RootStr:       root,
		Origin:        model.MountOriginProcfs,
		Visible:       true,
		Detached:      false,
	}
}

// ResolverOpts defines mount resolver options
type ResolverOpts struct {
	UseProcFS bool
}

// Resolver represents a cache for mountpoints and the corresponding file systems
type Resolver struct {
	opts            ResolverOpts
	cgroupsResolver *cgroup.Resolver
	statsdClient    statsd.ClientInterface
	lock            sync.RWMutex
	mounts          *simplelru.LRU[uint32, *model.Mount]
	pidToMounts     *cache.TwoLayersLRU[uint32, uint32, *model.Mount]
	minMountID      uint32 // used to find the first userspace visible mount ID
	redemption      *simplelru.LRU[uint32, *redemptionEntry]
	fallbackLimiter *utils.Limiter[uint64]

	// stats
	cacheHitsStats *atomic.Int64
	cacheMissStats *atomic.Int64
	procHitsStats  *atomic.Int64
	procMissStats  *atomic.Int64
}

// IsMountIDValid returns whether the mountID is valid
func (mr *Resolver) IsMountIDValid(mountID uint32) (bool, error) {
	if mountID == 0 {
		return false, ErrMountUndefined
	}

	if mountID < mr.minMountID {
		return false, ErrMountKernelID
	}

	return true, nil
}

// SyncCache Snapshots the current mount points of the system by reading through /proc/[pid]/mountinfo.
func (mr *Resolver) SyncCache(pid uint32) error {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	err := mr.syncPid(pid)

	// store the minimal mount ID found to use it as a reference
	if pid == 1 {
		for mountID := range mr.mounts.KeysIter() {
			if mr.minMountID == 0 || mr.minMountID > mountID {
				mr.minMountID = mountID
			}
		}
	}

	return err
}

func (mr *Resolver) syncPid(pid uint32) error {
	mnts, err := kernel.ParseMountInfoFile(int32(pid))
	if err != nil {
		return err
	}

	for _, mnt := range mnts {
		if m, exists := mr.mounts.Get(uint32(mnt.ID)); m != nil && exists {
			mr.updatePidMapping(m, pid)
			continue
		}

		m := newMountFromMountInfo(mnt)
		mr.insert(m, pid)
	}

	return nil
}

// syncCache update cache with the first working pid
func (mr *Resolver) syncCache(mountID uint32, pids []uint32) error {
	var err error

	for _, pid := range pids {
		key := uint64(mountID)<<32 | uint64(pid)
		if !mr.fallbackLimiter.Allow(key) {
			continue
		}

		if err = mr.syncPid(pid); err == nil {
			return nil
		}
	}

	return err
}

const openQueuePreAllocSize = 32 // should be enough to handle most of in queue mounts waiting to be deleted

func (mr *Resolver) delete(mount *model.Mount) {
	now := time.Now()

	mr.deleteOne(mount, now)

	openQueue := make([]uint32, 0, openQueuePreAllocSize)
	openQueue = append(openQueue, mount.MountID)

	for len(openQueue) != 0 {
		curr, rest := openQueue[len(openQueue)-1], openQueue[:len(openQueue)-1]
		openQueue = rest

		for child := range mr.mounts.ValuesIter() {
			if child.ParentPathKey.MountID == curr {
				openQueue = append(openQueue, child.MountID)
				mr.deleteOne(child, now)
			}
		}
	}
}

func (mr *Resolver) deleteOne(curr *model.Mount, now time.Time) {
	mr.mounts.Remove(curr.MountID)
	mr.pidToMounts.RemoveKey2(curr.MountID)

	entry := redemptionEntry{
		mount:      curr,
		insertedAt: now,
	}
	mr.redemption.Add(curr.MountID, &entry)
}

func (mr *Resolver) finalize(mount *model.Mount) {
	mr.mounts.Remove(mount.MountID)
}

// Delete a mount from the cache
func (mr *Resolver) Delete(mountID uint32) error {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	if m, exists := mr.mounts.Get(mountID); exists {
		mr.delete(m)
	} else {
		return &ErrMountNotFound{MountID: mountID}
	}

	return nil
}

// ResolveFilesystem returns the name of the filesystem
func (mr *Resolver) ResolveFilesystem(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (string, error) {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	mount, _, _, err := mr.resolveMount(mountID, device, pid, containerID)
	if err != nil {
		return model.UnknownFS, err
	}

	return mount.GetFSType(), nil
}

// Insert a new mount point in the cache
func (mr *Resolver) Insert(m model.Mount, pid uint32) error {
	if m.MountID == 0 {
		return ErrMountUndefined
	}

	mr.lock.Lock()
	defer mr.lock.Unlock()

	mr.insert(&m, pid)

	return nil
}

func (mr *Resolver) updatePidMapping(m *model.Mount, pid uint32) {
	if pid == 0 {
		return
	}

	mr.pidToMounts.Add(pid, m.MountID, m)
}

// DelPid removes the pid form the pid mapping
func (mr *Resolver) DelPid(pid uint32) {
	if pid == 0 {
		return
	}

	mr.lock.Lock()
	defer mr.lock.Unlock()

	mr.pidToMounts.RemoveKey1(pid)
}

func (mr *Resolver) insert(m *model.Mount, pid uint32) {
	// umount the previous one if exists
	if prev, ok := mr.mounts.Get(m.MountID); prev != nil && ok {
		// put the prev entry and the all the children in the redemption list
		mr.delete(prev)
		// force a finalize on the entry itself as it will be overridden by the new one
		mr.finalize(prev)
	} else if _, ok := mr.redemption.Get(m.MountID); ok {
		// this will call the eviction function that will call the finalize
		mr.redemption.Remove(m.MountID)
	}

	// if we're inserting a mountpoint from a kernel event (!= procfs) that isn't the root fs
	// then remove the leading slash from the mountpoint
	if len(m.Path) == 0 && m.MountPointStr != "/" {
		m.MountPointStr = strings.TrimPrefix(m.MountPointStr, "/")
	}

	if mr.minMountID > m.MountID {
		mr.minMountID = m.MountID
	}

	mr.mounts.Add(m.MountID, m)

	mr.updatePidMapping(m, pid)
}

func (mr *Resolver) getFromRedemption(mountID uint32) *model.Mount {
	entry, exists := mr.redemption.Get(mountID)
	if !exists || time.Since(entry.insertedAt) > redemptionTime {
		return nil
	}
	return entry.mount
}

func (mr *Resolver) lookupByMountID(mountID uint32) *model.Mount {
	if mount, ok := mr.mounts.Get(mountID); mount != nil && ok {
		return mount
	}

	return mr.getFromRedemption(mountID)
}

func (mr *Resolver) lookupByDevice(device uint32, pid uint32) *model.Mount {
	var result *model.Mount

	mr.pidToMounts.WalkInner(pid, func(_ uint32, mount *model.Mount) bool {
		if mount.Device == device {
			// should be consistent across all the mounts
			if result != nil && result.MountPointStr != mount.MountPointStr {
				result = nil
				return false
			}
			result = mount
		}
		return true
	})

	return result
}

func (mr *Resolver) lookupMount(mountID uint32, device uint32, pid uint32) (*model.Mount, model.MountSource, model.MountOrigin) {
	mount := mr.lookupByMountID(mountID)
	if mount != nil {
		return mount, model.MountSourceMountID, mount.Origin
	}

	mount = mr.lookupByDevice(device, pid)
	if mount == nil {
		return nil, model.MountSourceUnknown, model.MountOriginUnknown
	}
	return mount, model.MountSourceDevice, mount.Origin
}

func (mr *Resolver) _getMountPath(mountID uint32, device uint32, pid uint32, cache map[uint32]bool) (string, model.MountSource, model.MountOrigin, error) {
	if _, err := mr.IsMountIDValid(mountID); err != nil {
		return "", model.MountSourceUnknown, model.MountOriginUnknown, err
	}

	mount, source, origin := mr.lookupMount(mountID, device, pid)
	if mount == nil {
		return "", source, origin, &ErrMountNotFound{MountID: mountID}
	}

	if len(mount.Path) > 0 {
		return mount.Path, source, origin, nil
	}

	mountPointStr := mount.MountPointStr
	if mountPointStr == "/" {
		return mountPointStr, source, mount.Origin, nil
	}

	// avoid infinite loop
	if _, exists := cache[mountID]; exists {
		return "", source, mount.Origin, ErrMountLoop
	}
	cache[mountID] = true

	if mount.Detached {
		// Detached mount
		return "/", source, mount.Origin, nil
	}

	if mount.ParentPathKey.MountID == 0 {
		return "", source, mount.Origin, ErrMountUndefined
	}

	parentMountPath, parentSource, parentOrigin, err := mr._getMountPath(mount.ParentPathKey.MountID, mount.Device, pid, cache)
	if err != nil {
		return "", parentSource, parentOrigin, err
	}
	mountPointStr = path.Join(parentMountPath, mountPointStr)

	if parentSource != model.MountSourceMountID {
		source = parentSource
	}

	if parentOrigin != model.MountOriginEvent {
		origin = parentOrigin
	}

	if len(mountPointStr) == 0 {
		return "", source, origin, ErrMountPathEmpty
	}

	mount.Path = mountPointStr

	return mountPointStr, source, origin, nil
}

func (mr *Resolver) getMountPath(mountID uint32, device uint32, pid uint32) (string, model.MountSource, model.MountOrigin, error) {
	return mr._getMountPath(mountID, device, pid, map[uint32]bool{})
}

// ResolveMountRoot returns the root of a mount identified by its mount ID.
func (mr *Resolver) ResolveMountRoot(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (string, model.MountSource, model.MountOrigin, error) {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	return mr.resolveMountRoot(mountID, device, pid, containerID)
}

func (mr *Resolver) resolveMountRoot(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (string, model.MountSource, model.MountOrigin, error) {
	mount, source, origin, err := mr.resolveMount(mountID, device, pid, containerID)
	if err != nil {
		return "", source, origin, err
	}
	return mount.RootStr, source, origin, err
}

// ResolveMountPath returns the path of a mount identified by its mount ID.
func (mr *Resolver) ResolveMountPath(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (string, model.MountSource, model.MountOrigin, error) {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	return mr.resolveMountPath(mountID, device, pid, containerID)
}

func (mr *Resolver) syncCacheMiss() {
	mr.procMissStats.Inc()
}

func (mr *Resolver) reSyncCache(mountID uint32, pids []uint32, containerID containerutils.ContainerID, workload *cmodel.CacheEntry) error {
	if workload != nil {
		pids = append(pids, workload.GetPIDs()...)
	} else if len(containerID) == 0 && !slices.Contains(pids, 1) {
		pids = append(pids, 1)
	}

	if err := mr.syncCache(mountID, pids); err != nil {
		mr.syncCacheMiss()
		return err
	}

	return nil
}

func (mr *Resolver) resolveMountPath(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (string, model.MountSource, model.MountOrigin, error) {
	if _, err := mr.IsMountIDValid(mountID); err != nil {
		return "", model.MountSourceUnknown, model.MountOriginUnknown, err
	}

	// force a resolution here to make sure the LRU keeps doing its job and doesn't evict important entries
	workload, _ := mr.cgroupsResolver.GetWorkload(containerID)

	path, source, origin, err := mr.getMountPath(mountID, device, pid)
	if err == nil {
		mr.cacheHitsStats.Inc()
		return path, source, origin, nil
	}
	mr.cacheMissStats.Inc()

	if !mr.opts.UseProcFS {
		return "", model.MountSourceUnknown, model.MountOriginUnknown, &ErrMountNotFound{MountID: mountID}
	}

	if err := mr.reSyncCache(mountID, []uint32{pid}, containerID, workload); err != nil {
		return "", model.MountSourceUnknown, model.MountOriginUnknown, err
	}

	path, source, origin, err = mr.getMountPath(mountID, device, pid)
	if err == nil {
		mr.procHitsStats.Inc()
		return path, source, origin, nil
	}
	mr.procMissStats.Inc()

	return "", model.MountSourceUnknown, model.MountOriginUnknown, err
}

// ResolveMount returns the mount
func (mr *Resolver) ResolveMount(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (*model.Mount, model.MountSource, model.MountOrigin, error) {
	mr.lock.Lock()
	defer mr.lock.Unlock()

	return mr.resolveMount(mountID, device, pid, containerID)
}

func (mr *Resolver) resolveMount(mountID uint32, device uint32, pid uint32, containerID containerutils.ContainerID) (*model.Mount, model.MountSource, model.MountOrigin, error) {
	if _, err := mr.IsMountIDValid(mountID); err != nil {
		return nil, model.MountSourceUnknown, model.MountOriginUnknown, err
	}

	// force a resolution here to make sure the LRU keeps doing its job and doesn't evict important entries
	workload, _ := mr.cgroupsResolver.GetWorkload(containerID)

	mount, source, origin := mr.lookupMount(mountID, device, pid)
	if mount != nil {
		mr.cacheHitsStats.Inc()
		return mount, source, origin, nil
	}
	mr.cacheMissStats.Inc()

	if !mr.opts.UseProcFS {
		return nil, model.MountSourceUnknown, model.MountOriginUnknown, &ErrMountNotFound{MountID: mountID}
	}

	if err := mr.reSyncCache(mountID, []uint32{pid}, containerID, workload); err != nil {
		return nil, model.MountSourceUnknown, model.MountOriginUnknown, err
	}

	if mount, ok := mr.mounts.Get(mountID); mount != nil && ok {
		mr.procHitsStats.Inc()
		return mount, model.MountSourceMountID, mount.Origin, nil
	}
	mr.procMissStats.Inc()

	return nil, model.MountSourceUnknown, model.MountOriginUnknown, &ErrMountNotFound{MountID: mountID}
}

// GetVFSLinkDentryPosition gets VFS link dentry position
func GetVFSLinkDentryPosition(kernelVersion *skernel.Version) uint64 {
	position := uint64(2)

	if kernelVersion.Code != 0 && kernelVersion.Code >= skernel.Kernel5_12 {
		position = 3
	}

	return position
}

// GetVFSMKDirDentryPosition gets VFS MKDir dentry position
func GetVFSMKDirDentryPosition(kernelVersion *skernel.Version) uint64 {
	position := uint64(2)

	if kernelVersion.Code != 0 && kernelVersion.Code >= skernel.Kernel5_12 {
		position = 3
	}

	return position
}

// GetVFSSetxattrDentryPosition gets VFS set xattr dentry position
func GetVFSSetxattrDentryPosition(kernelVersion *skernel.Version) uint64 {
	position := uint64(1)

	if kernelVersion.Code != 0 && kernelVersion.Code >= skernel.Kernel5_12 {
		position = 2
	}

	return position
}

// GetVFSRemovexattrDentryPosition gets VFS remove xattr dentry position
func GetVFSRemovexattrDentryPosition(kernelVersion *skernel.Version) uint64 {
	position := uint64(1)

	if kernelVersion.Code != 0 && kernelVersion.Code >= skernel.Kernel5_12 {
		position = 2
	}

	return position
}

// SendStats sends metrics about the current state of the mount resolver
func (mr *Resolver) SendStats() error {
	mr.lock.RLock()
	defer mr.lock.RUnlock()

	if err := mr.statsdClient.Count(metrics.MetricMountResolverHits, mr.cacheHitsStats.Swap(0), []string{metrics.CacheTag}, 1.0); err != nil {
		return err
	}

	if err := mr.statsdClient.Count(metrics.MetricMountResolverMiss, mr.cacheMissStats.Swap(0), []string{metrics.CacheTag}, 1.0); err != nil {
		return err
	}

	if err := mr.statsdClient.Count(metrics.MetricMountResolverHits, mr.procHitsStats.Swap(0), []string{metrics.ProcFSTag}, 1.0); err != nil {
		return err
	}

	if err := mr.statsdClient.Count(metrics.MetricMountResolverMiss, mr.procMissStats.Swap(0), []string{metrics.ProcFSTag}, 1.0); err != nil {
		return err
	}

	return mr.statsdClient.Gauge(metrics.MetricMountResolverCacheSize, float64(mr.mounts.Len()), []string{}, 1.0)
}

// ToJSON return a json version of the cache
func (mr *Resolver) ToJSON() ([]byte, error) {
	dump := struct {
		Entries []json.RawMessage
	}{}

	mr.lock.RLock()
	defer mr.lock.RUnlock()

	for mount := range mr.mounts.ValuesIter() {
		d, err := json.Marshal(mount)
		if err == nil {
			dump.Entries = append(dump.Entries, d)
		}
	}

	return json.Marshal(dump)
}

const (
	// mounts LRU limit: 100000 mounts
	mountsLimit = 100000
	// pidToMounts LRU limits: 1000 pids, and 1000 mounts per pid
	pidLimit          = 1000
	mountsPerPidLimit = 1000
)

// NewResolver instantiates a new mount resolver
func NewResolver(statsdClient statsd.ClientInterface, cgroupsResolver *cgroup.Resolver, opts ResolverOpts) (*Resolver, error) {
	mounts, err := simplelru.NewLRU[uint32, *model.Mount](mountsLimit, nil)
	if err != nil {
		return nil, err
	}

	pidToMounts, err := cache.NewTwoLayersLRU[uint32, uint32, *model.Mount](pidLimit * mountsPerPidLimit)
	if err != nil {
		return nil, err
	}

	mr := &Resolver{
		opts:            opts,
		statsdClient:    statsdClient,
		cgroupsResolver: cgroupsResolver,
		lock:            sync.RWMutex{},
		mounts:          mounts,
		pidToMounts:     pidToMounts,
		cacheHitsStats:  atomic.NewInt64(0),
		procHitsStats:   atomic.NewInt64(0),
		cacheMissStats:  atomic.NewInt64(0),
		procMissStats:   atomic.NewInt64(0),
	}

	redemption, err := simplelru.NewLRU(1024, func(_ uint32, entry *redemptionEntry) {
		mr.finalize(entry.mount)
	})
	if err != nil {
		return nil, err
	}
	mr.redemption = redemption

	// create a rate limiter that allows for 64 mount IDs
	limiter, err := utils.NewLimiter[uint64](64, numAllowedMountIDsToResolvePerPeriod, fallbackLimiterPeriod)
	if err != nil {
		return nil, err
	}
	mr.fallbackLimiter = limiter

	return mr, nil
}
