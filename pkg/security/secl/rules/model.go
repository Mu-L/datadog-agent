// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package rules holds rules related files
package rules

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// MacroID represents the ID of a macro
type MacroID = string

// CombinePolicy represents the policy to use to combine rules and macros
type CombinePolicy = string

// Combine policies
const (
	NoPolicy       CombinePolicy = ""
	MergePolicy    CombinePolicy = "merge"
	OverridePolicy CombinePolicy = "override"
)

// OverrideField defines a combine field
type OverrideField = string

const (
	// OverrideAllFields used to override all the fields
	OverrideAllFields OverrideField = "all"
	// OverrideActionFields used to override the actions
	OverrideActionFields OverrideField = "actions"
	// OverrideEveryField used to override the every field
	OverrideEveryField OverrideField = "every"
	// OverrideTagsField used to override the tags
	OverrideTagsField OverrideField = "tags"
	// OverrideProductTagsField used to override the product_tags field
	OverrideProductTagsField OverrideField = "product_tags"
)

// OverrideOptions defines combine options
type OverrideOptions struct {
	Fields []OverrideField `yaml:"fields" json:"fields" jsonschema:"enum=all,enum=expression,enum=actions,enum=every,enum=tags"`
}

// MacroDefinition holds the definition of a macro
type MacroDefinition struct {
	ID                     MacroID       `yaml:"id" json:"id"`
	Expression             string        `yaml:"expression" json:"expression,omitempty" jsonschema:"oneof_required=MacroWithExpression"`
	Description            string        `yaml:"description" json:"description,omitempty"`
	AgentVersionConstraint string        `yaml:"agent_version" json:"agent_version,omitempty"`
	Filters                []string      `yaml:"filters" json:"filters,omitempty"`
	Values                 []string      `yaml:"values" json:"values,omitempty" jsonschema:"oneof_required=MacroWithValues"`
	Combine                CombinePolicy `yaml:"combine" json:"combine,omitempty" jsonschema:"enum=merge,enum=override"`
}

// RuleID represents the ID of a rule
type RuleID = string

// RuleDefinition holds the definition of a rule
type RuleDefinition struct {
	ID                     RuleID                 `yaml:"id,omitempty" json:"id"`
	Version                string                 `yaml:"version,omitempty" json:"version,omitempty"`
	Expression             string                 `yaml:"expression" json:"expression,omitempty"`
	Description            string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Tags                   map[string]string      `yaml:"tags,omitempty" json:"tags,omitempty"`
	ProductTags            []string               `yaml:"product_tags,omitempty" json:"product_tags,omitempty"`
	AgentVersionConstraint string                 `yaml:"agent_version,omitempty" json:"agent_version,omitempty"`
	Filters                []string               `yaml:"filters,omitempty" json:"filters,omitempty"`
	Disabled               bool                   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Combine                CombinePolicy          `yaml:"combine,omitempty" json:"combine,omitempty" jsonschema:"enum=override"`
	OverrideOptions        OverrideOptions        `yaml:"override_options,omitempty" json:"override_options,omitempty"`
	Actions                []*ActionDefinition    `yaml:"actions,omitempty" json:"actions,omitempty"`
	Every                  *HumanReadableDuration `yaml:"every,omitempty" json:"every,omitempty"`
	RateLimiterToken       []string               `yaml:"limiter_token,omitempty" json:"limiter_token,omitempty"`
	Silent                 bool                   `yaml:"silent,omitempty" json:"silent,omitempty"`
	GroupID                string                 `yaml:"group_id,omitempty" json:"group_id,omitempty"`
}

// GetTag returns the tag value associated with a tag key
func (rd *RuleDefinition) GetTag(tagKey string) (string, bool) {
	tagValue, ok := rd.Tags[tagKey]
	if ok {
		return tagValue, true
	}
	return "", false
}

// ActionName defines an action name
type ActionName = string

const (
	// KillAction name of the kill action
	KillAction ActionName = "kill"
	// SetAction name of the set action
	SetAction ActionName = "set"
	// CoreDumpAction name of the core dump action
	CoreDumpAction ActionName = "coredump"
	// HashAction name of the hash action
	HashAction ActionName = "hash"
	// LogAction name of the log action
	LogAction ActionName = "log"
)

// ActionDefinition describes a rule action section
type ActionDefinition struct {
	Filter   *string             `yaml:"filter" json:"filter,omitempty"`
	Set      *SetDefinition      `yaml:"set" json:"set,omitempty" jsonschema:"oneof_required=SetAction"`
	Kill     *KillDefinition     `yaml:"kill" json:"kill,omitempty" jsonschema:"oneof_required=KillAction"`
	CoreDump *CoreDumpDefinition `yaml:"coredump" json:"coredump,omitempty" jsonschema:"oneof_required=CoreDumpAction"`
	Hash     *HashDefinition     `yaml:"hash" json:"hash,omitempty" jsonschema:"oneof_required=HashAction"`
	Log      *LogDefinition      `yaml:"log" json:"log,omitempty" jsonschema:"oneof_required=LogAction"`
}

// Name returns the name of the action
func (a *ActionDefinition) Name() ActionName {
	switch {
	case a.Set != nil:
		return SetAction
	case a.Kill != nil:
		return KillAction
	case a.CoreDump != nil:
		return CoreDumpAction
	case a.Hash != nil:
		return HashAction
	case a.Log != nil:
		return LogAction
	default:
		return ""
	}
}

// Scope describes the scope variables
type Scope string

// SetDefinition describes the 'set' section of a rule action
type SetDefinition struct {
	Name         string                 `yaml:"name" json:"name"`
	Value        interface{}            `yaml:"value" json:"value,omitempty" jsonschema:"oneof_required=SetWithValue,oneof_type=string;integer;boolean;array"`
	DefaultValue interface{}            `yaml:"default_value" json:"default_value,omitempty" jsonschema:"oneof_type=string;integer;boolean;array"`
	Field        string                 `yaml:"field" json:"field,omitempty" jsonschema:"oneof_required=SetWithField"`
	Expression   string                 `yaml:"expression" json:"expression,omitempty"`
	Append       bool                   `yaml:"append" json:"append,omitempty"`
	Scope        Scope                  `yaml:"scope" json:"scope,omitempty" jsonschema:"enum=process,enum=container,enum=cgroup"`
	ScopeField   string                 `yaml:"scope_field" json:"scope_field,omitempty"`
	Size         int                    `yaml:"size" json:"size,omitempty"`
	TTL          *HumanReadableDuration `yaml:"ttl" json:"ttl,omitempty"`
	Private      bool                   `yaml:"private" json:"private,omitempty"`
	Inherited    bool                   `yaml:"inherited" json:"inherited,omitempty"`
}

// KillDefinition describes the 'kill' section of a rule action
type KillDefinition struct {
	Signal                    string `yaml:"signal" json:"signal" jsonschema:"description=A valid signal name,example=SIGKILL,example=SIGTERM"`
	Scope                     string `yaml:"scope" json:"scope,omitempty" jsonschema:"enum=process,enum=container"`
	DisableContainerDisarmer  bool   `yaml:"disable_container_disarmer" json:"disable_container_disarmer,omitempty" jsonschema:"description=Set to true to disable the rule kill action automatic container disarmer safeguard"`
	DisableExecutableDisarmer bool   `yaml:"disable_executable_disarmer" json:"disable_executable_disarmer,omitempty" jsonschema:"description=Set to true to disable the rule kill action automatic executable disarmer safeguard"`
}

// CoreDumpDefinition describes the 'coredump' action
type CoreDumpDefinition struct {
	Process       bool `yaml:"process" json:"process,omitempty" jsonschema:"anyof_required=CoreDumpWithProcess"`
	Mount         bool `yaml:"mount" json:"mount,omitempty" jsonschema:"anyof_required=CoreDumpWithMount"`
	Dentry        bool `yaml:"dentry" json:"dentry,omitempty" jsonschema:"anyof_required=CoreDumpWithDentry"`
	NoCompression bool `yaml:"no_compression" json:"no_compression,omitempty"`
}

// HashDefinition describes the 'hash' section of a rule action
type HashDefinition struct{}

// LogDefinition describes the 'log' section of a rule action
type LogDefinition struct {
	Level   string
	Message string
}

// OnDemandHookPoint represents a hook point definition
type OnDemandHookPoint struct {
	Name      string
	IsSyscall bool
	Args      []HookPointArg
}

// HookPointArg represents the definition of a hook point argument
type HookPointArg struct {
	N    int
	Kind string
}

// PolicyDef represents a policy file definition
type PolicyDef struct {
	Version string             `yaml:"version,omitempty" json:"version"`
	Macros  []*MacroDefinition `yaml:"macros,omitempty" json:"macros,omitempty"`
	Rules   []*RuleDefinition  `yaml:"rules" json:"rules"`
}

// HumanReadableDuration represents a duration that can unmarshalled from YAML from a human readable format (like `10m`)
// or from a regular integer
type HumanReadableDuration struct {
	time.Duration
}

// GetDuration returns the duration embedded in the HumanReadableDuration, or 0 if nil
func (d *HumanReadableDuration) GetDuration() time.Duration {
	if d == nil {
		return 0
	}
	return d.Duration
}

// MarshalYAML marshals a duration to a human readable format
func (d *HumanReadableDuration) MarshalYAML() (interface{}, error) {
	return d.String(), nil
}

// UnmarshalYAML unmarshals a duration from a human readable format or from an integer
func (d *HumanReadableDuration) UnmarshalYAML(n *yaml.Node) error {
	var v interface{}
	if err := n.Decode(&v); err != nil {
		return err
	}
	switch value := v.(type) {
	case int:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid duration: (yaml type: %T)", v)
	}
}

var _ yaml.Marshaler = (*HumanReadableDuration)(nil)
var _ yaml.Unmarshaler = (*HumanReadableDuration)(nil)
