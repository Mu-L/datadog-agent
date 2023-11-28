// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.
// Code generated - DO NOT EDIT.

//go:build darwin
// +build darwin

package model

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"time"
)

// GetContainerCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetContainerCreatedAt() int {
	zeroValue := 0
	if ev.BaseEvent.ContainerContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveContainerCreatedAt(ev, ev.BaseEvent.ContainerContext)
}

// GetContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetContainerId() string {
	zeroValue := ""
	if ev.BaseEvent.ContainerContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveContainerID(ev, ev.BaseEvent.ContainerContext)
}

// GetContainerTags returns the value of the field, resolving if necessary
func (ev *Event) GetContainerTags() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ContainerContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveContainerTags(ev, ev.BaseEvent.ContainerContext)
}

// GetEventTimestamp returns the value of the field, resolving if necessary
func (ev *Event) GetEventTimestamp() int {
	return ev.FieldHandlers.ResolveEventTimestamp(ev, &ev.BaseEvent)
}

// GetExecArgsFlags returns the value of the field, resolving if necessary
func (ev *Event) GetExecArgsFlags() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exec.Process)
}

// GetExecArgsOptions returns the value of the field, resolving if necessary
func (ev *Event) GetExecArgsOptions() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exec.Process)
}

// GetExecArgv returns the value of the field, resolving if necessary
func (ev *Event) GetExecArgv() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exec.Process)
}

// GetExecCmdline returns the value of the field, resolving if necessary
func (ev *Event) GetExecCmdline() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLine(ev, ev.Exec.Process)
}

// GetExecCmdlineScrubbed returns the value of the field, resolving if necessary
func (ev *Event) GetExecCmdlineScrubbed() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLineScrubbed(ev, ev.Exec.Process)
}

// GetExecContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetExecContainerId() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.ContainerID
}

// GetExecCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetExecCreatedAt() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exec.Process)
}

// GetExecEnvp returns the value of the field, resolving if necessary
func (ev *Event) GetExecEnvp() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exec.Process)
}

// GetExecEnvs returns the value of the field, resolving if necessary
func (ev *Event) GetExecEnvs() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exec.Process)
}

// GetExecExecTime returns the value of the field, resolving if necessary
func (ev *Event) GetExecExecTime() time.Time {
	zeroValue := time.Time{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.ExecTime
}

// GetExecExitTime returns the value of the field, resolving if necessary
func (ev *Event) GetExecExitTime() time.Time {
	zeroValue := time.Time{}
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.ExitTime
}

// GetExecFileName returns the value of the field, resolving if necessary
func (ev *Event) GetExecFileName() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent)
}

// GetExecFileNameLength returns the value of the field, resolving if necessary
func (ev *Event) GetExecFileNameLength() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exec.Process.FileEvent))
}

// GetExecFilePath returns the value of the field, resolving if necessary
func (ev *Event) GetExecFilePath() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent)
}

// GetExecFilePathLength returns the value of the field, resolving if necessary
func (ev *Event) GetExecFilePathLength() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exec.Process.FileEvent))
}

// GetExecGid returns the value of the field, resolving if necessary
func (ev *Event) GetExecGid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.GID
}

// GetExecGroup returns the value of the field, resolving if necessary
func (ev *Event) GetExecGroup() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.Group
}

// GetExecPid returns the value of the field, resolving if necessary
func (ev *Event) GetExecPid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.PIDContext.Pid
}

// GetExecPpid returns the value of the field, resolving if necessary
func (ev *Event) GetExecPpid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.PPid
}

// GetExecUid returns the value of the field, resolving if necessary
func (ev *Event) GetExecUid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.UID
}

// GetExecUser returns the value of the field, resolving if necessary
func (ev *Event) GetExecUser() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exec" {
		return zeroValue
	}
	if ev.Exec.Process == nil {
		return zeroValue
	}
	return ev.Exec.Process.User
}

// GetExitArgsFlags returns the value of the field, resolving if necessary
func (ev *Event) GetExitArgsFlags() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.Exit.Process)
}

// GetExitArgsOptions returns the value of the field, resolving if necessary
func (ev *Event) GetExitArgsOptions() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.Exit.Process)
}

// GetExitArgv returns the value of the field, resolving if necessary
func (ev *Event) GetExitArgv() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgv(ev, ev.Exit.Process)
}

// GetExitCause returns the value of the field, resolving if necessary
func (ev *Event) GetExitCause() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	return ev.Exit.Cause
}

// GetExitCmdline returns the value of the field, resolving if necessary
func (ev *Event) GetExitCmdline() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLine(ev, ev.Exit.Process)
}

// GetExitCmdlineScrubbed returns the value of the field, resolving if necessary
func (ev *Event) GetExitCmdlineScrubbed() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLineScrubbed(ev, ev.Exit.Process)
}

// GetExitCode returns the value of the field, resolving if necessary
func (ev *Event) GetExitCode() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	return ev.Exit.Code
}

// GetExitContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetExitContainerId() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.ContainerID
}

// GetExitCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetExitCreatedAt() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.Exit.Process)
}

// GetExitEnvp returns the value of the field, resolving if necessary
func (ev *Event) GetExitEnvp() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.Exit.Process)
}

// GetExitEnvs returns the value of the field, resolving if necessary
func (ev *Event) GetExitEnvs() []string {
	zeroValue := []string{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.Exit.Process)
}

// GetExitExecTime returns the value of the field, resolving if necessary
func (ev *Event) GetExitExecTime() time.Time {
	zeroValue := time.Time{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.ExecTime
}

// GetExitExitTime returns the value of the field, resolving if necessary
func (ev *Event) GetExitExitTime() time.Time {
	zeroValue := time.Time{}
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.ExitTime
}

// GetExitFileName returns the value of the field, resolving if necessary
func (ev *Event) GetExitFileName() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent)
}

// GetExitFileNameLength returns the value of the field, resolving if necessary
func (ev *Event) GetExitFileNameLength() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.Exit.Process.FileEvent))
}

// GetExitFilePath returns the value of the field, resolving if necessary
func (ev *Event) GetExitFilePath() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent)
}

// GetExitFilePathLength returns the value of the field, resolving if necessary
func (ev *Event) GetExitFilePathLength() int {
	zeroValue := 0
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.Exit.Process.FileEvent))
}

// GetExitGid returns the value of the field, resolving if necessary
func (ev *Event) GetExitGid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.GID
}

// GetExitGroup returns the value of the field, resolving if necessary
func (ev *Event) GetExitGroup() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.Group
}

// GetExitPid returns the value of the field, resolving if necessary
func (ev *Event) GetExitPid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.PIDContext.Pid
}

// GetExitPpid returns the value of the field, resolving if necessary
func (ev *Event) GetExitPpid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.PPid
}

// GetExitUid returns the value of the field, resolving if necessary
func (ev *Event) GetExitUid() uint32 {
	zeroValue := uint32(0)
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.UID
}

// GetExitUser returns the value of the field, resolving if necessary
func (ev *Event) GetExitUser() string {
	zeroValue := ""
	if ev.GetEventType().String() != "exit" {
		return zeroValue
	}
	if ev.Exit.Process == nil {
		return zeroValue
	}
	return ev.Exit.Process.User
}

// GetProcessAncestorsArgsFlags returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsArgsFlags() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessArgsFlags(ev, &element.ProcessContext.Process)
		values = append(values, result...)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsArgsOptions returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsArgsOptions() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessArgsOptions(ev, &element.ProcessContext.Process)
		values = append(values, result...)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsArgv returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsArgv() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessArgv(ev, &element.ProcessContext.Process)
		values = append(values, result...)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsCmdline returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsCmdline() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessCmdLine(ev, &element.ProcessContext.Process)
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsCmdlineScrubbed returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsCmdlineScrubbed() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessCmdLineScrubbed(ev, &element.ProcessContext.Process)
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsContainerId() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.ContainerID
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsCreatedAt() []int {
	zeroValue := []int{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []int
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := int(ev.FieldHandlers.ResolveProcessCreatedAt(ev, &element.ProcessContext.Process))
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsEnvp returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsEnvp() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessEnvp(ev, &element.ProcessContext.Process)
		values = append(values, result...)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsEnvs returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsEnvs() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveProcessEnvs(ev, &element.ProcessContext.Process)
		values = append(values, result...)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsFileName returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsFileName() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveFileBasename(ev, &element.ProcessContext.Process.FileEvent)
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsFileNameLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsFileNameLength() []int {
	zeroValue := []int{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []int
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := len(ev.FieldHandlers.ResolveFileBasename(ev, &element.ProcessContext.Process.FileEvent))
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsFilePath returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsFilePath() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := ev.FieldHandlers.ResolveFilePath(ev, &element.ProcessContext.Process.FileEvent)
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsFilePathLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsFilePathLength() []int {
	zeroValue := []int{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []int
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := len(ev.FieldHandlers.ResolveFilePath(ev, &element.ProcessContext.Process.FileEvent))
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsGid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsGid() []uint32 {
	zeroValue := []uint32{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []uint32
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.GID
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsGroup returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsGroup() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.Group
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsPid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsPid() []uint32 {
	zeroValue := []uint32{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []uint32
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.PIDContext.Pid
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsPpid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsPpid() []uint32 {
	zeroValue := []uint32{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []uint32
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.PPid
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsUid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsUid() []uint32 {
	zeroValue := []uint32{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []uint32
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.UID
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessAncestorsUser returns the value of the field, resolving if necessary
func (ev *Event) GetProcessAncestorsUser() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Ancestor == nil {
		return zeroValue
	}
	var values []string
	ctx := eval.NewContext(ev)
	iterator := &ProcessAncestorsIterator{}
	ptr := iterator.Front(ctx)
	for ptr != nil {
		element := (*ProcessCacheEntry)(ptr)
		result := element.ProcessContext.Process.User
		values = append(values, result)
		ptr = iterator.Next()
	}
	return values
}

// GetProcessArgsFlags returns the value of the field, resolving if necessary
func (ev *Event) GetProcessArgsFlags() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsFlags(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessArgsOptions returns the value of the field, resolving if necessary
func (ev *Event) GetProcessArgsOptions() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgsOptions(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessArgv returns the value of the field, resolving if necessary
func (ev *Event) GetProcessArgv() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessArgv(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessCmdline returns the value of the field, resolving if necessary
func (ev *Event) GetProcessCmdline() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLine(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessCmdlineScrubbed returns the value of the field, resolving if necessary
func (ev *Event) GetProcessCmdlineScrubbed() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCmdLineScrubbed(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetProcessContainerId() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.ContainerID
}

// GetProcessCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetProcessCreatedAt() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessCreatedAt(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessEnvp returns the value of the field, resolving if necessary
func (ev *Event) GetProcessEnvp() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvp(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessEnvs returns the value of the field, resolving if necessary
func (ev *Event) GetProcessEnvs() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveProcessEnvs(ev, &ev.BaseEvent.ProcessContext.Process)
}

// GetProcessExecTime returns the value of the field, resolving if necessary
func (ev *Event) GetProcessExecTime() time.Time {
	zeroValue := time.Time{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.ExecTime
}

// GetProcessExitTime returns the value of the field, resolving if necessary
func (ev *Event) GetProcessExitTime() time.Time {
	zeroValue := time.Time{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.ExitTime
}

// GetProcessFileName returns the value of the field, resolving if necessary
func (ev *Event) GetProcessFileName() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFileBasename(ev, &ev.BaseEvent.ProcessContext.Process.FileEvent)
}

// GetProcessFileNameLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessFileNameLength() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.BaseEvent.ProcessContext.Process.FileEvent))
}

// GetProcessFilePath returns the value of the field, resolving if necessary
func (ev *Event) GetProcessFilePath() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.FieldHandlers.ResolveFilePath(ev, &ev.BaseEvent.ProcessContext.Process.FileEvent)
}

// GetProcessFilePathLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessFilePathLength() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.BaseEvent.ProcessContext.Process.FileEvent))
}

// GetProcessGid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessGid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.GID
}

// GetProcessGroup returns the value of the field, resolving if necessary
func (ev *Event) GetProcessGroup() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.Group
}

// GetProcessParentArgsFlags returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentArgsFlags() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return []string{}
	}
	return ev.FieldHandlers.ResolveProcessArgsFlags(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentArgsOptions returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentArgsOptions() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return []string{}
	}
	return ev.FieldHandlers.ResolveProcessArgsOptions(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentArgv returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentArgv() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return []string{}
	}
	return ev.FieldHandlers.ResolveProcessArgv(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentCmdline returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentCmdline() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.FieldHandlers.ResolveProcessCmdLine(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentCmdlineScrubbed returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentCmdlineScrubbed() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.FieldHandlers.ResolveProcessCmdLineScrubbed(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentContainerId returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentContainerId() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.BaseEvent.ProcessContext.Parent.ContainerID
}

// GetProcessParentCreatedAt returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentCreatedAt() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return 0
	}
	return ev.FieldHandlers.ResolveProcessCreatedAt(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentEnvp returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentEnvp() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return []string{}
	}
	return ev.FieldHandlers.ResolveProcessEnvp(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentEnvs returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentEnvs() []string {
	zeroValue := []string{}
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return []string{}
	}
	return ev.FieldHandlers.ResolveProcessEnvs(ev, ev.BaseEvent.ProcessContext.Parent)
}

// GetProcessParentFileName returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentFileName() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.FieldHandlers.ResolveFileBasename(ev, &ev.BaseEvent.ProcessContext.Parent.FileEvent)
}

// GetProcessParentFileNameLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentFileNameLength() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFileBasename(ev, &ev.BaseEvent.ProcessContext.Parent.FileEvent))
}

// GetProcessParentFilePath returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentFilePath() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.FieldHandlers.ResolveFilePath(ev, &ev.BaseEvent.ProcessContext.Parent.FileEvent)
}

// GetProcessParentFilePathLength returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentFilePathLength() int {
	zeroValue := 0
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	return len(ev.FieldHandlers.ResolveFilePath(ev, &ev.BaseEvent.ProcessContext.Parent.FileEvent))
}

// GetProcessParentGid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentGid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return uint32(0)
	}
	return ev.BaseEvent.ProcessContext.Parent.GID
}

// GetProcessParentGroup returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentGroup() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.BaseEvent.ProcessContext.Parent.Group
}

// GetProcessParentPid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentPid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return uint32(0)
	}
	return ev.BaseEvent.ProcessContext.Parent.PIDContext.Pid
}

// GetProcessParentPpid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentPpid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return uint32(0)
	}
	return ev.BaseEvent.ProcessContext.Parent.PPid
}

// GetProcessParentUid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentUid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return uint32(0)
	}
	return ev.BaseEvent.ProcessContext.Parent.UID
}

// GetProcessParentUser returns the value of the field, resolving if necessary
func (ev *Event) GetProcessParentUser() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	if ev.BaseEvent.ProcessContext.Parent == nil {
		return zeroValue
	}
	if !ev.BaseEvent.ProcessContext.HasParent() {
		return ""
	}
	return ev.BaseEvent.ProcessContext.Parent.User
}

// GetProcessPid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessPid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.PIDContext.Pid
}

// GetProcessPpid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessPpid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.PPid
}

// GetProcessUid returns the value of the field, resolving if necessary
func (ev *Event) GetProcessUid() uint32 {
	zeroValue := uint32(0)
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.UID
}

// GetProcessUser returns the value of the field, resolving if necessary
func (ev *Event) GetProcessUser() string {
	zeroValue := ""
	if ev.BaseEvent.ProcessContext == nil {
		return zeroValue
	}
	return ev.BaseEvent.ProcessContext.Process.User
}

// GetTimestamp returns the value of the field, resolving if necessary
func (ev *Event) GetTimestamp() time.Time {
	return ev.FieldHandlers.ResolveEventTime(ev, &ev.BaseEvent)
}
