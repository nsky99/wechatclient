// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: SnsTimeLineWithType.proto

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

type SnsTimeLineWithTypeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest *BaseRequest `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	SelectType  *uint64      `protobuf:"varint,2,opt,name=selectType" json:"selectType,omitempty"`
}

func (x *SnsTimeLineWithTypeRequest) Reset() {
	*x = SnsTimeLineWithTypeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsTimeLineWithType_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsTimeLineWithTypeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsTimeLineWithTypeRequest) ProtoMessage() {}

func (x *SnsTimeLineWithTypeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_SnsTimeLineWithType_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsTimeLineWithTypeRequest.ProtoReflect.Descriptor instead.
func (*SnsTimeLineWithTypeRequest) Descriptor() ([]byte, []int) {
	return file_SnsTimeLineWithType_proto_rawDescGZIP(), []int{0}
}

func (x *SnsTimeLineWithTypeRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *SnsTimeLineWithTypeRequest) GetSelectType() uint64 {
	if x != nil && x.SelectType != nil {
		return *x.SelectType
	}
	return 0
}

type SnsTimeLineWithTypeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse *BaseResponse `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	ObjectCount  *uint32       `protobuf:"varint,2,req,name=objectCount" json:"objectCount,omitempty"`
	ObjectList   []*SnsObject  `protobuf:"bytes,3,rep,name=objectList" json:"objectList,omitempty"`
}

func (x *SnsTimeLineWithTypeResponse) Reset() {
	*x = SnsTimeLineWithTypeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsTimeLineWithType_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsTimeLineWithTypeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsTimeLineWithTypeResponse) ProtoMessage() {}

func (x *SnsTimeLineWithTypeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_SnsTimeLineWithType_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsTimeLineWithTypeResponse.ProtoReflect.Descriptor instead.
func (*SnsTimeLineWithTypeResponse) Descriptor() ([]byte, []int) {
	return file_SnsTimeLineWithType_proto_rawDescGZIP(), []int{1}
}

func (x *SnsTimeLineWithTypeResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *SnsTimeLineWithTypeResponse) GetObjectCount() uint32 {
	if x != nil && x.ObjectCount != nil {
		return *x.ObjectCount
	}
	return 0
}

func (x *SnsTimeLineWithTypeResponse) GetObjectList() []*SnsObject {
	if x != nil {
		return x.ObjectList
	}
	return nil
}

var File_SnsTimeLineWithType_proto protoreflect.FileDescriptor

var file_SnsTimeLineWithType_proto_rawDesc = []byte{
	0x0a, 0x19, 0x53, 0x6e, 0x73, 0x54, 0x69, 0x6d, 0x65, 0x4c, 0x69, 0x6e, 0x65, 0x57, 0x69, 0x74,
	0x68, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63,
	0x72, 0x6f, 0x4d, 0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x53, 0x6e, 0x73, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x6c, 0x0a, 0x1a, 0x53, 0x6e, 0x73, 0x54, 0x69, 0x6d, 0x65, 0x4c, 0x69,
	0x6e, 0x65, 0x57, 0x69, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70,
	0x65, 0x22, 0x9e, 0x01, 0x0a, 0x1b, 0x53, 0x6e, 0x73, 0x54, 0x69, 0x6d, 0x65, 0x4c, 0x69, 0x6e,
	0x65, 0x57, 0x69, 0x74, 0x68, 0x54, 0x79, 0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2a, 0x0a, 0x0a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x4c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x53, 0x6e, 0x73,
	0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x0a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4c, 0x69,
	0x73, 0x74, 0x42, 0x0c, 0x5a, 0x0a, 0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_SnsTimeLineWithType_proto_rawDescOnce sync.Once
	file_SnsTimeLineWithType_proto_rawDescData = file_SnsTimeLineWithType_proto_rawDesc
)

func file_SnsTimeLineWithType_proto_rawDescGZIP() []byte {
	file_SnsTimeLineWithType_proto_rawDescOnce.Do(func() {
		file_SnsTimeLineWithType_proto_rawDescData = protoimpl.X.CompressGZIP(file_SnsTimeLineWithType_proto_rawDescData)
	})
	return file_SnsTimeLineWithType_proto_rawDescData
}

var file_SnsTimeLineWithType_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_SnsTimeLineWithType_proto_goTypes = []interface{}{
	(*SnsTimeLineWithTypeRequest)(nil),  // 0: SnsTimeLineWithTypeRequest
	(*SnsTimeLineWithTypeResponse)(nil), // 1: SnsTimeLineWithTypeResponse
	(*BaseRequest)(nil),                 // 2: BaseRequest
	(*BaseResponse)(nil),                // 3: BaseResponse
	(*SnsObject)(nil),                   // 4: SnsObject
}
var file_SnsTimeLineWithType_proto_depIdxs = []int32{
	2, // 0: SnsTimeLineWithTypeRequest.baseRequest:type_name -> BaseRequest
	3, // 1: SnsTimeLineWithTypeResponse.baseResponse:type_name -> BaseResponse
	4, // 2: SnsTimeLineWithTypeResponse.objectList:type_name -> SnsObject
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_SnsTimeLineWithType_proto_init() }
func file_SnsTimeLineWithType_proto_init() {
	if File_SnsTimeLineWithType_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	file_MicroSnsBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SnsTimeLineWithType_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsTimeLineWithTypeRequest); i {
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
		file_SnsTimeLineWithType_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsTimeLineWithTypeResponse); i {
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
			RawDescriptor: file_SnsTimeLineWithType_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SnsTimeLineWithType_proto_goTypes,
		DependencyIndexes: file_SnsTimeLineWithType_proto_depIdxs,
		MessageInfos:      file_SnsTimeLineWithType_proto_msgTypes,
	}.Build()
	File_SnsTimeLineWithType_proto = out.File
	file_SnsTimeLineWithType_proto_rawDesc = nil
	file_SnsTimeLineWithType_proto_goTypes = nil
	file_SnsTimeLineWithType_proto_depIdxs = nil
}