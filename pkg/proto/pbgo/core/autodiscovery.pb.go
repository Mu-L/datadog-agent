// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: datadog/autodiscovery/autodiscovery.proto

package core

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ConfigEventType int32

const (
	ConfigEventType_SCHEDULE   ConfigEventType = 0
	ConfigEventType_UNSCHEDULE ConfigEventType = 1
)

// Enum value maps for ConfigEventType.
var (
	ConfigEventType_name = map[int32]string{
		0: "SCHEDULE",
		1: "UNSCHEDULE",
	}
	ConfigEventType_value = map[string]int32{
		"SCHEDULE":   0,
		"UNSCHEDULE": 1,
	}
)

func (x ConfigEventType) Enum() *ConfigEventType {
	p := new(ConfigEventType)
	*p = x
	return p
}

func (x ConfigEventType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ConfigEventType) Descriptor() protoreflect.EnumDescriptor {
	return file_datadog_autodiscovery_autodiscovery_proto_enumTypes[0].Descriptor()
}

func (ConfigEventType) Type() protoreflect.EnumType {
	return &file_datadog_autodiscovery_autodiscovery_proto_enumTypes[0]
}

func (x ConfigEventType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ConfigEventType.Descriptor instead.
func (ConfigEventType) EnumDescriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{0}
}

type KubeNamespacedName struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Namespace     string                 `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *KubeNamespacedName) Reset() {
	*x = KubeNamespacedName{}
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KubeNamespacedName) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KubeNamespacedName) ProtoMessage() {}

func (x *KubeNamespacedName) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KubeNamespacedName.ProtoReflect.Descriptor instead.
func (*KubeNamespacedName) Descriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{0}
}

func (x *KubeNamespacedName) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *KubeNamespacedName) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type KubeEndpointsIdentifier struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	KubeNamespacedName *KubeNamespacedName    `protobuf:"bytes,1,opt,name=kubeNamespacedName,proto3" json:"kubeNamespacedName,omitempty"`
	Resolve            string                 `protobuf:"bytes,2,opt,name=resolve,proto3" json:"resolve,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *KubeEndpointsIdentifier) Reset() {
	*x = KubeEndpointsIdentifier{}
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KubeEndpointsIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KubeEndpointsIdentifier) ProtoMessage() {}

func (x *KubeEndpointsIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KubeEndpointsIdentifier.ProtoReflect.Descriptor instead.
func (*KubeEndpointsIdentifier) Descriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{1}
}

func (x *KubeEndpointsIdentifier) GetKubeNamespacedName() *KubeNamespacedName {
	if x != nil {
		return x.KubeNamespacedName
	}
	return nil
}

func (x *KubeEndpointsIdentifier) GetResolve() string {
	if x != nil {
		return x.Resolve
	}
	return ""
}

type AdvancedADIdentifier struct {
	state         protoimpl.MessageState   `protogen:"open.v1"`
	KubeService   *KubeNamespacedName      `protobuf:"bytes,1,opt,name=kubeService,proto3" json:"kubeService,omitempty"`
	KubeEndpoints *KubeEndpointsIdentifier `protobuf:"bytes,2,opt,name=kubeEndpoints,proto3" json:"kubeEndpoints,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AdvancedADIdentifier) Reset() {
	*x = AdvancedADIdentifier{}
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AdvancedADIdentifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AdvancedADIdentifier) ProtoMessage() {}

func (x *AdvancedADIdentifier) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AdvancedADIdentifier.ProtoReflect.Descriptor instead.
func (*AdvancedADIdentifier) Descriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{2}
}

func (x *AdvancedADIdentifier) GetKubeService() *KubeNamespacedName {
	if x != nil {
		return x.KubeService
	}
	return nil
}

func (x *AdvancedADIdentifier) GetKubeEndpoints() *KubeEndpointsIdentifier {
	if x != nil {
		return x.KubeEndpoints
	}
	return nil
}

type Config struct {
	state                   protoimpl.MessageState  `protogen:"open.v1"`
	Name                    string                  `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Instances               [][]byte                `protobuf:"bytes,2,rep,name=instances,proto3" json:"instances,omitempty"`
	InitConfig              []byte                  `protobuf:"bytes,3,opt,name=initConfig,proto3" json:"initConfig,omitempty"`
	MetricConfig            []byte                  `protobuf:"bytes,4,opt,name=metricConfig,proto3" json:"metricConfig,omitempty"`
	LogsConfig              []byte                  `protobuf:"bytes,5,opt,name=logsConfig,proto3" json:"logsConfig,omitempty"`
	AdIdentifiers           []string                `protobuf:"bytes,6,rep,name=adIdentifiers,proto3" json:"adIdentifiers,omitempty"`
	AdvancedAdIdentifiers   []*AdvancedADIdentifier `protobuf:"bytes,7,rep,name=advancedAdIdentifiers,proto3" json:"advancedAdIdentifiers,omitempty"`
	Provider                string                  `protobuf:"bytes,8,opt,name=provider,proto3" json:"provider,omitempty"`
	ServiceId               string                  `protobuf:"bytes,9,opt,name=serviceId,proto3" json:"serviceId,omitempty"`
	TaggerEntity            string                  `protobuf:"bytes,10,opt,name=taggerEntity,proto3" json:"taggerEntity,omitempty"`
	ClusterCheck            bool                    `protobuf:"varint,11,opt,name=clusterCheck,proto3" json:"clusterCheck,omitempty"`
	NodeName                string                  `protobuf:"bytes,12,opt,name=nodeName,proto3" json:"nodeName,omitempty"`
	Source                  string                  `protobuf:"bytes,13,opt,name=source,proto3" json:"source,omitempty"`
	IgnoreAutodiscoveryTags bool                    `protobuf:"varint,14,opt,name=ignoreAutodiscoveryTags,proto3" json:"ignoreAutodiscoveryTags,omitempty"`
	MetricsExcluded         bool                    `protobuf:"varint,15,opt,name=metricsExcluded,proto3" json:"metricsExcluded,omitempty"`
	LogsExcluded            bool                    `protobuf:"varint,16,opt,name=logsExcluded,proto3" json:"logsExcluded,omitempty"`
	EventType               ConfigEventType         `protobuf:"varint,17,opt,name=eventType,proto3,enum=datadog.autodiscovery.ConfigEventType" json:"eventType,omitempty"`
	unknownFields           protoimpl.UnknownFields
	sizeCache               protoimpl.SizeCache
}

func (x *Config) Reset() {
	*x = Config{}
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{3}
}

func (x *Config) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Config) GetInstances() [][]byte {
	if x != nil {
		return x.Instances
	}
	return nil
}

func (x *Config) GetInitConfig() []byte {
	if x != nil {
		return x.InitConfig
	}
	return nil
}

func (x *Config) GetMetricConfig() []byte {
	if x != nil {
		return x.MetricConfig
	}
	return nil
}

func (x *Config) GetLogsConfig() []byte {
	if x != nil {
		return x.LogsConfig
	}
	return nil
}

func (x *Config) GetAdIdentifiers() []string {
	if x != nil {
		return x.AdIdentifiers
	}
	return nil
}

func (x *Config) GetAdvancedAdIdentifiers() []*AdvancedADIdentifier {
	if x != nil {
		return x.AdvancedAdIdentifiers
	}
	return nil
}

func (x *Config) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}

func (x *Config) GetServiceId() string {
	if x != nil {
		return x.ServiceId
	}
	return ""
}

func (x *Config) GetTaggerEntity() string {
	if x != nil {
		return x.TaggerEntity
	}
	return ""
}

func (x *Config) GetClusterCheck() bool {
	if x != nil {
		return x.ClusterCheck
	}
	return false
}

func (x *Config) GetNodeName() string {
	if x != nil {
		return x.NodeName
	}
	return ""
}

func (x *Config) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *Config) GetIgnoreAutodiscoveryTags() bool {
	if x != nil {
		return x.IgnoreAutodiscoveryTags
	}
	return false
}

func (x *Config) GetMetricsExcluded() bool {
	if x != nil {
		return x.MetricsExcluded
	}
	return false
}

func (x *Config) GetLogsExcluded() bool {
	if x != nil {
		return x.LogsExcluded
	}
	return false
}

func (x *Config) GetEventType() ConfigEventType {
	if x != nil {
		return x.EventType
	}
	return ConfigEventType_SCHEDULE
}

type AutodiscoveryStreamResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Configs       []*Config              `protobuf:"bytes,1,rep,name=configs,proto3" json:"configs,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AutodiscoveryStreamResponse) Reset() {
	*x = AutodiscoveryStreamResponse{}
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AutodiscoveryStreamResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AutodiscoveryStreamResponse) ProtoMessage() {}

func (x *AutodiscoveryStreamResponse) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_autodiscovery_autodiscovery_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AutodiscoveryStreamResponse.ProtoReflect.Descriptor instead.
func (*AutodiscoveryStreamResponse) Descriptor() ([]byte, []int) {
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP(), []int{4}
}

func (x *AutodiscoveryStreamResponse) GetConfigs() []*Config {
	if x != nil {
		return x.Configs
	}
	return nil
}

var File_datadog_autodiscovery_autodiscovery_proto protoreflect.FileDescriptor

const file_datadog_autodiscovery_autodiscovery_proto_rawDesc = "" +
	"\n" +
	")datadog/autodiscovery/autodiscovery.proto\x12\x15datadog.autodiscovery\"F\n" +
	"\x12KubeNamespacedName\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1c\n" +
	"\tnamespace\x18\x02 \x01(\tR\tnamespace\"\x8e\x01\n" +
	"\x17KubeEndpointsIdentifier\x12Y\n" +
	"\x12kubeNamespacedName\x18\x01 \x01(\v2).datadog.autodiscovery.KubeNamespacedNameR\x12kubeNamespacedName\x12\x18\n" +
	"\aresolve\x18\x02 \x01(\tR\aresolve\"\xb9\x01\n" +
	"\x14AdvancedADIdentifier\x12K\n" +
	"\vkubeService\x18\x01 \x01(\v2).datadog.autodiscovery.KubeNamespacedNameR\vkubeService\x12T\n" +
	"\rkubeEndpoints\x18\x02 \x01(\v2..datadog.autodiscovery.KubeEndpointsIdentifierR\rkubeEndpoints\"\xab\x05\n" +
	"\x06Config\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1c\n" +
	"\tinstances\x18\x02 \x03(\fR\tinstances\x12\x1e\n" +
	"\n" +
	"initConfig\x18\x03 \x01(\fR\n" +
	"initConfig\x12\"\n" +
	"\fmetricConfig\x18\x04 \x01(\fR\fmetricConfig\x12\x1e\n" +
	"\n" +
	"logsConfig\x18\x05 \x01(\fR\n" +
	"logsConfig\x12$\n" +
	"\radIdentifiers\x18\x06 \x03(\tR\radIdentifiers\x12a\n" +
	"\x15advancedAdIdentifiers\x18\a \x03(\v2+.datadog.autodiscovery.AdvancedADIdentifierR\x15advancedAdIdentifiers\x12\x1a\n" +
	"\bprovider\x18\b \x01(\tR\bprovider\x12\x1c\n" +
	"\tserviceId\x18\t \x01(\tR\tserviceId\x12\"\n" +
	"\ftaggerEntity\x18\n" +
	" \x01(\tR\ftaggerEntity\x12\"\n" +
	"\fclusterCheck\x18\v \x01(\bR\fclusterCheck\x12\x1a\n" +
	"\bnodeName\x18\f \x01(\tR\bnodeName\x12\x16\n" +
	"\x06source\x18\r \x01(\tR\x06source\x128\n" +
	"\x17ignoreAutodiscoveryTags\x18\x0e \x01(\bR\x17ignoreAutodiscoveryTags\x12(\n" +
	"\x0fmetricsExcluded\x18\x0f \x01(\bR\x0fmetricsExcluded\x12\"\n" +
	"\flogsExcluded\x18\x10 \x01(\bR\flogsExcluded\x12D\n" +
	"\teventType\x18\x11 \x01(\x0e2&.datadog.autodiscovery.ConfigEventTypeR\teventType\"V\n" +
	"\x1bAutodiscoveryStreamResponse\x127\n" +
	"\aconfigs\x18\x01 \x03(\v2\x1d.datadog.autodiscovery.ConfigR\aconfigs*/\n" +
	"\x0fConfigEventType\x12\f\n" +
	"\bSCHEDULE\x10\x00\x12\x0e\n" +
	"\n" +
	"UNSCHEDULE\x10\x01B\x15Z\x13pkg/proto/pbgo/coreb\x06proto3"

var (
	file_datadog_autodiscovery_autodiscovery_proto_rawDescOnce sync.Once
	file_datadog_autodiscovery_autodiscovery_proto_rawDescData []byte
)

func file_datadog_autodiscovery_autodiscovery_proto_rawDescGZIP() []byte {
	file_datadog_autodiscovery_autodiscovery_proto_rawDescOnce.Do(func() {
		file_datadog_autodiscovery_autodiscovery_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_datadog_autodiscovery_autodiscovery_proto_rawDesc), len(file_datadog_autodiscovery_autodiscovery_proto_rawDesc)))
	})
	return file_datadog_autodiscovery_autodiscovery_proto_rawDescData
}

var file_datadog_autodiscovery_autodiscovery_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_datadog_autodiscovery_autodiscovery_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_datadog_autodiscovery_autodiscovery_proto_goTypes = []any{
	(ConfigEventType)(0),                // 0: datadog.autodiscovery.ConfigEventType
	(*KubeNamespacedName)(nil),          // 1: datadog.autodiscovery.KubeNamespacedName
	(*KubeEndpointsIdentifier)(nil),     // 2: datadog.autodiscovery.KubeEndpointsIdentifier
	(*AdvancedADIdentifier)(nil),        // 3: datadog.autodiscovery.AdvancedADIdentifier
	(*Config)(nil),                      // 4: datadog.autodiscovery.Config
	(*AutodiscoveryStreamResponse)(nil), // 5: datadog.autodiscovery.AutodiscoveryStreamResponse
}
var file_datadog_autodiscovery_autodiscovery_proto_depIdxs = []int32{
	1, // 0: datadog.autodiscovery.KubeEndpointsIdentifier.kubeNamespacedName:type_name -> datadog.autodiscovery.KubeNamespacedName
	1, // 1: datadog.autodiscovery.AdvancedADIdentifier.kubeService:type_name -> datadog.autodiscovery.KubeNamespacedName
	2, // 2: datadog.autodiscovery.AdvancedADIdentifier.kubeEndpoints:type_name -> datadog.autodiscovery.KubeEndpointsIdentifier
	3, // 3: datadog.autodiscovery.Config.advancedAdIdentifiers:type_name -> datadog.autodiscovery.AdvancedADIdentifier
	0, // 4: datadog.autodiscovery.Config.eventType:type_name -> datadog.autodiscovery.ConfigEventType
	4, // 5: datadog.autodiscovery.AutodiscoveryStreamResponse.configs:type_name -> datadog.autodiscovery.Config
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_datadog_autodiscovery_autodiscovery_proto_init() }
func file_datadog_autodiscovery_autodiscovery_proto_init() {
	if File_datadog_autodiscovery_autodiscovery_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_datadog_autodiscovery_autodiscovery_proto_rawDesc), len(file_datadog_autodiscovery_autodiscovery_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_datadog_autodiscovery_autodiscovery_proto_goTypes,
		DependencyIndexes: file_datadog_autodiscovery_autodiscovery_proto_depIdxs,
		EnumInfos:         file_datadog_autodiscovery_autodiscovery_proto_enumTypes,
		MessageInfos:      file_datadog_autodiscovery_autodiscovery_proto_msgTypes,
	}.Build()
	File_datadog_autodiscovery_autodiscovery_proto = out.File
	file_datadog_autodiscovery_autodiscovery_proto_goTypes = nil
	file_datadog_autodiscovery_autodiscovery_proto_depIdxs = nil
}
