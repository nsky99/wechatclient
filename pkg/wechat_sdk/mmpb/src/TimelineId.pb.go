// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: TimelineId.proto

package micromsg

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TimelineId struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MaxId *uint64 `protobuf:"varint,4,opt,name=max_id,json=maxId" json:"max_id,omitempty"`
}

func (x *TimelineId) Reset() {
	*x = TimelineId{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TimelineId_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TimelineId) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TimelineId) ProtoMessage() {}

func (x *TimelineId) ProtoReflect() protoreflect.Message {
	mi := &file_TimelineId_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TimelineId.ProtoReflect.Descriptor instead.
func (*TimelineId) Descriptor() ([]byte, []int) {
	return file_TimelineId_proto_rawDescGZIP(), []int{0}
}

func (x *TimelineId) GetMaxId() uint64 {
	if x != nil && x.MaxId != nil {
		return *x.MaxId
	}
	return 0
}

type TimelineInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TimelineId *TimelineId `protobuf:"bytes,2,opt,name=timelineId" json:"timelineId,omitempty"`
}

func (x *TimelineInfo) Reset() {
	*x = TimelineInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TimelineId_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TimelineInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TimelineInfo) ProtoMessage() {}

func (x *TimelineInfo) ProtoReflect() protoreflect.Message {
	mi := &file_TimelineId_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TimelineInfo.ProtoReflect.Descriptor instead.
func (*TimelineInfo) Descriptor() ([]byte, []int) {
	return file_TimelineId_proto_rawDescGZIP(), []int{1}
}

func (x *TimelineInfo) GetTimelineId() *TimelineId {
	if x != nil {
		return x.TimelineId
	}
	return nil
}

var File_TimelineId_proto protoreflect.FileDescriptor

var file_TimelineId_proto_rawDesc = []byte{
	0x0a, 0x10, 0x54, 0x69, 0x6d, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x49, 0x64, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x23, 0x0a, 0x0a, 0x54, 0x69, 0x6d, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x49, 0x64,
	0x12, 0x15, 0x0a, 0x06, 0x6d, 0x61, 0x78, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x05, 0x6d, 0x61, 0x78, 0x49, 0x64, 0x22, 0x3b, 0x0a, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x6c,
	0x69, 0x6e, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2b, 0x0a, 0x0a, 0x74, 0x69, 0x6d, 0x65, 0x6c,
	0x69, 0x6e, 0x65, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x49, 0x64, 0x52, 0x0a, 0x74, 0x69, 0x6d, 0x65, 0x6c, 0x69,
	0x6e, 0x65, 0x49, 0x64, 0x42, 0x0c, 0x5a, 0x0a, 0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d,
	0x73, 0x67,
}

var (
	file_TimelineId_proto_rawDescOnce sync.Once
	file_TimelineId_proto_rawDescData = file_TimelineId_proto_rawDesc
)

func file_TimelineId_proto_rawDescGZIP() []byte {
	file_TimelineId_proto_rawDescOnce.Do(func() {
		file_TimelineId_proto_rawDescData = protoimpl.X.CompressGZIP(file_TimelineId_proto_rawDescData)
	})
	return file_TimelineId_proto_rawDescData
}

var file_TimelineId_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_TimelineId_proto_goTypes = []interface{}{
	(*TimelineId)(nil),   // 0: TimelineId
	(*TimelineInfo)(nil), // 1: TimelineInfo
}
var file_TimelineId_proto_depIdxs = []int32{
	0, // 0: TimelineInfo.timelineId:type_name -> TimelineId
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_TimelineId_proto_init() }
func file_TimelineId_proto_init() {
	if File_TimelineId_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_TimelineId_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TimelineId); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_TimelineId_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TimelineInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_TimelineId_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TimelineId_proto_goTypes,
		DependencyIndexes: file_TimelineId_proto_depIdxs,
		MessageInfos:      file_TimelineId_proto_msgTypes,
	}.Build()
	File_TimelineId_proto = out.File
	file_TimelineId_proto_rawDesc = nil
	file_TimelineId_proto_goTypes = nil
	file_TimelineId_proto_depIdxs = nil
}
