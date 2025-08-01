// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package metadata defines types for describing data about a device.
package metadata

import "github.com/DataDog/datadog-agent/pkg/networkdevice/integrations"

// PayloadMetadataBatchSize is the number of resources per event payload
// Resources are devices, interfaces, etc
const PayloadMetadataBatchSize = 100

// DeviceStatus enum type
type DeviceStatus int32

const (
	// DeviceStatusReachable means the device can be reached by snmp integration
	DeviceStatusReachable = DeviceStatus(1)
	// DeviceStatusUnreachable means the device cannot be reached by snmp integration
	DeviceStatusUnreachable = DeviceStatus(2)
)

//nolint:revive // TODO(NDM) Fix revive linter
type IDType string

const (
	// IDTypeMacAddress represent mac address in `00:00:00:00:00:00` format
	IDTypeMacAddress = "mac_address"
	//nolint:revive // TODO(NDM) Fix revive linter
	IDTypeInterfaceName = "interface_name"
	//nolint:revive // TODO(NDM) Fix revive linter
	IDTypeInterfaceAlias = "interface_alias"
)

// NetworkDevicesMetadata contains network devices metadata
type NetworkDevicesMetadata struct {
	Subnet           string                   `json:"subnet,omitempty"`
	Namespace        string                   `json:"namespace"`
	Integration      integrations.Integration `json:"integration"`
	Devices          []DeviceMetadata         `json:"devices,omitempty"`
	Interfaces       []InterfaceMetadata      `json:"interfaces,omitempty"`
	IPAddresses      []IPAddressMetadata      `json:"ip_addresses,omitempty"`
	Links            []TopologyLinkMetadata   `json:"links,omitempty"`
	VPNTunnels       []VPNTunnelMetadata      `json:"vpn_tunnels,omitempty"`
	NetflowExporters []NetflowExporter        `json:"netflow_exporters,omitempty"`
	Diagnoses        []DiagnosisMetadata      `json:"diagnoses,omitempty"`
	DeviceOIDs       []DeviceOID              `json:"device_oids,omitempty"`
	DeviceScanStatus *ScanStatusMetadata      `json:"scan_status,omitempty"`
	CollectTimestamp int64                    `json:"collect_timestamp"`
}

// DeviceMetadata contains device metadata
type DeviceMetadata struct {
	ID             string       `json:"id"`
	IDTags         []string     `json:"id_tags"` // id_tags is the input to produce device.id, it's also used to correlated with device metrics.
	Tags           []string     `json:"tags"`
	IPAddress      string       `json:"ip_address"`
	Status         DeviceStatus `json:"status"`
	PingStatus     DeviceStatus `json:"ping_status,omitempty"`
	Name           string       `json:"name,omitempty"`
	Description    string       `json:"description,omitempty"`
	SysObjectID    string       `json:"sys_object_id,omitempty"`
	Location       string       `json:"location,omitempty"`
	Profile        string       `json:"profile,omitempty"`
	ProfileVersion uint64       `json:"profile_version,omitempty"`
	Vendor         string       `json:"vendor,omitempty"`
	Subnet         string       `json:"subnet,omitempty"`
	SerialNumber   string       `json:"serial_number,omitempty"`
	Version        string       `json:"version,omitempty"`
	ProductName    string       `json:"product_name,omitempty"`
	Model          string       `json:"model,omitempty"`
	OsName         string       `json:"os_name,omitempty"`
	OsVersion      string       `json:"os_version,omitempty"`
	OsHostname     string       `json:"os_hostname,omitempty"`
	Integration    string       `json:"integration,omitempty"` // indicates the source of the data SNMP, meraki_api, etc.
	DeviceType     string       `json:"device_type,omitempty"`
}

// DeviceOID device scan oid data
type DeviceOID struct {
	DeviceID string `json:"device_id"`
	OID      string `json:"oid"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

// ScanStatus type for the different possible scan statuses
type ScanStatus string

const (
	// ScanStatusInProgress represents a scan in progress
	ScanStatusInProgress ScanStatus = "in progress"
	// ScanStatusCompleted represents a completed scan
	ScanStatusCompleted ScanStatus = "completed"
	// ScanStatusError represents a scan error
	ScanStatusError ScanStatus = "error"
)

// ScanType type for the different possible scan types manual or rc_triggered
type ScanType string

const (
	// ManualScan represents a manual scan
	ManualScan ScanType = "manual"
	// RCTriggeredScan represents a rc triggered scan
	RCTriggeredScan ScanType = "rc_triggered"
)

// ScanStatusMetadata contains scan status metadata
type ScanStatusMetadata struct {
	DeviceID   string     `json:"device_id"`
	ScanStatus ScanStatus `json:"scan_status"`
	ScanType   ScanType   `json:"scan_type,omitempty"`
}

// InterfaceMetadata contains interface metadata
type InterfaceMetadata struct {
	DeviceID      string        `json:"device_id"`
	IDTags        []string      `json:"id_tags"`               // used to correlate with interface metrics
	Index         int32         `json:"index"`                 // IF-MIB ifIndex type is InterfaceIndex (Integer32 (1..2147483647))
	RawID         string        `json:"raw_id,omitempty"`      // used to uniquely identify the interface in the context of the device
	RawIDType     string        `json:"raw_id_type,omitempty"` // used to indicate the type of identifier used (i.e. portId for Meraki switches, uplink for Meraki uplinks, blank for SNMP for compatibility)
	Name          string        `json:"name,omitempty"`
	Alias         string        `json:"alias,omitempty"`
	Description   string        `json:"description,omitempty"`
	MacAddress    string        `json:"mac_address,omitempty"`
	AdminStatus   IfAdminStatus `json:"admin_status,omitempty"`   // IF-MIB ifAdminStatus type is INTEGER
	OperStatus    IfOperStatus  `json:"oper_status,omitempty"`    // IF-MIB ifOperStatus type is INTEGER
	MerakiEnabled *bool         `json:"meraki_enabled,omitempty"` // enabled bool for Meraki devices, use a pointer to determine if the value was actually sent
	MerakiStatus  string        `json:"meraki_status,omitempty"`  // status for Meraki devices
}

// IPAddressMetadata contains ip address metadata
type IPAddressMetadata struct {
	InterfaceID string `json:"interface_id"`
	IPAddress   string `json:"ip_address"`
	Prefixlen   int32  `json:"prefixlen,omitempty"`
}

// TopologyLinkDevice contain device link data
type TopologyLinkDevice struct {
	DDID        string `json:"dd_id,omitempty"`
	ID          string `json:"id,omitempty"`
	IDType      string `json:"id_type,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
}

// TopologyLinkInterface contain interface link data
type TopologyLinkInterface struct {
	DDID        string `json:"dd_id,omitempty"`
	ID          string `json:"id"`
	IDType      string `json:"id_type,omitempty"`
	Description string `json:"description,omitempty"`
}

// TopologyLinkSide contain data for remote or local side of the link
type TopologyLinkSide struct {
	Device    *TopologyLinkDevice    `json:"device,omitempty"`
	Interface *TopologyLinkInterface `json:"interface,omitempty"`
}

// TopologyLinkMetadata contains topology interface to interface links metadata
type TopologyLinkMetadata struct {
	ID          string            `json:"id"`
	SourceType  string            `json:"source_type"`
	Integration string            `json:"integration,omitempty"`
	Local       *TopologyLinkSide `json:"local"`
	Remote      *TopologyLinkSide `json:"remote"`
}

// VPNProtocol represents the different possible VPN protocols
type VPNProtocol string

const (
	// IPsec represents the IPsec protocol
	IPsec VPNProtocol = "ipsec"
)

// VPNTunnelMetadata contains VPN tunnel metadata
type VPNTunnelMetadata struct {
	DeviceID        string           `json:"device_id"`
	InterfaceID     string           `json:"interface_id,omitempty"`
	LocalOutsideIP  string           `json:"local_outside_ip"`
	RemoteOutsideIP string           `json:"remote_outside_ip"`
	Status          string           `json:"status"`
	Protocol        VPNProtocol      `json:"protocol"`
	RouteAddresses  []string         `json:"route_addresses"`
	Options         VPNTunnelOptions `json:"options,omitempty"`
}

// VPNTunnelOptions contains VPN tunnel options for each protocol
type VPNTunnelOptions struct {
	IPsecOptions IPsecOptions `json:"ipsec_options,omitempty"`
}

// IPsecOptions contains IPsec VPN tunnel options
type IPsecOptions struct {
	LifeSize int32 `json:"life_size"`
	LifeTime int32 `json:"life_time"`
}

// NetflowExporter contains netflow exporters info
type NetflowExporter struct {
	ID        string `json:"id"` // used by backend as unique id (e.g. in cache)
	IPAddress string `json:"ip_address"`
	FlowType  string `json:"flow_type"`
}

// Diagnosis contain data for a diagnosis
type Diagnosis struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Code     string `json:"code"`
}

// DiagnosisMetadata contains diagnoses info
type DiagnosisMetadata struct {
	ResourceType string      `json:"resource_type"`
	ResourceID   string      `json:"resource_id"`
	Diagnoses    []Diagnosis `json:"diagnoses"`
}
