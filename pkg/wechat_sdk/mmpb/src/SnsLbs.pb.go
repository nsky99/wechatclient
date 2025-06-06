// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: SnsLbs.proto

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

type SnsLbsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest *BaseRequest `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	OpCode      *uint32      `protobuf:"varint,2,req,name=opCode" json:"opCode,omitempty"`
	Longitude   *float32     `protobuf:"fixed32,3,req,name=longitude" json:"longitude,omitempty"`
	Latitude    *float32     `protobuf:"fixed32,4,req,name=latitude" json:"latitude,omitempty"`
	Precision   *int32       `protobuf:"varint,5,req,name=precision" json:"precision,omitempty"`
	MacAddr     *string      `protobuf:"bytes,6,opt,name=macAddr" json:"macAddr,omitempty"`
	CellId      *string      `protobuf:"bytes,7,opt,name=cellId" json:"cellId,omitempty"`
	GpsSource   *int32       `protobuf:"varint,8,req,name=gpsSource" json:"gpsSource,omitempty"`
	SbTime      *uint32      `protobuf:"varint,9,req,name=sbTime" json:"sbTime,omitempty"`
}

func (x *SnsLbsRequest) Reset() {
	*x = SnsLbsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsLbs_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsLbsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsLbsRequest) ProtoMessage() {}

func (x *SnsLbsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_SnsLbs_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsLbsRequest.ProtoReflect.Descriptor instead.
func (*SnsLbsRequest) Descriptor() ([]byte, []int) {
	return file_SnsLbs_proto_rawDescGZIP(), []int{0}
}

func (x *SnsLbsRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *SnsLbsRequest) GetOpCode() uint32 {
	if x != nil && x.OpCode != nil {
		return *x.OpCode
	}
	return 0
}

func (x *SnsLbsRequest) GetLongitude() float32 {
	if x != nil && x.Longitude != nil {
		return *x.Longitude
	}
	return 0
}

func (x *SnsLbsRequest) GetLatitude() float32 {
	if x != nil && x.Latitude != nil {
		return *x.Latitude
	}
	return 0
}

func (x *SnsLbsRequest) GetPrecision() int32 {
	if x != nil && x.Precision != nil {
		return *x.Precision
	}
	return 0
}

func (x *SnsLbsRequest) GetMacAddr() string {
	if x != nil && x.MacAddr != nil {
		return *x.MacAddr
	}
	return ""
}

func (x *SnsLbsRequest) GetCellId() string {
	if x != nil && x.CellId != nil {
		return *x.CellId
	}
	return ""
}

func (x *SnsLbsRequest) GetGpsSource() int32 {
	if x != nil && x.GpsSource != nil {
		return *x.GpsSource
	}
	return 0
}

func (x *SnsLbsRequest) GetSbTime() uint32 {
	if x != nil && x.SbTime != nil {
		return *x.SbTime
	}
	return 0
}

type SnsLbsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse *BaseResponse        `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	ContactCount *uint32              `protobuf:"varint,2,req,name=contactCount" json:"contactCount,omitempty"`
	ContactList  []*SnsLbsContactInfo `protobuf:"bytes,3,rep,name=contactList" json:"contactList,omitempty"`
}

func (x *SnsLbsResponse) Reset() {
	*x = SnsLbsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsLbs_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsLbsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsLbsResponse) ProtoMessage() {}

func (x *SnsLbsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_SnsLbs_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsLbsResponse.ProtoReflect.Descriptor instead.
func (*SnsLbsResponse) Descriptor() ([]byte, []int) {
	return file_SnsLbs_proto_rawDescGZIP(), []int{1}
}

func (x *SnsLbsResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *SnsLbsResponse) GetContactCount() uint32 {
	if x != nil && x.ContactCount != nil {
		return *x.ContactCount
	}
	return 0
}

func (x *SnsLbsResponse) GetContactList() []*SnsLbsContactInfo {
	if x != nil {
		return x.ContactList
	}
	return nil
}

var File_SnsLbs_proto protoreflect.FileDescriptor

var file_SnsLbs_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x53, 0x6e, 0x73, 0x4c, 0x62, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12,
	0x4d, 0x69, 0x63, 0x72, 0x6f, 0x4d, 0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x53, 0x6e, 0x73, 0x42, 0x61, 0x73, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x97, 0x02, 0x0a, 0x0d, 0x53, 0x6e, 0x73, 0x4c, 0x62,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x62, 0x61, 0x73, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0c, 0x2e,
	0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x62, 0x61, 0x73,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x70, 0x43, 0x6f,
	0x64, 0x65, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x06, 0x6f, 0x70, 0x43, 0x6f, 0x64, 0x65,
	0x12, 0x1c, 0x0a, 0x09, 0x6c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x03, 0x20,
	0x02, 0x28, 0x02, 0x52, 0x09, 0x6c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1a,
	0x0a, 0x08, 0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x04, 0x20, 0x02, 0x28, 0x02,
	0x52, 0x08, 0x6c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x72,
	0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x02, 0x28, 0x05, 0x52, 0x09, 0x70,
	0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x61, 0x63, 0x41,
	0x64, 0x64, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x61, 0x63, 0x41, 0x64,
	0x64, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x65, 0x6c, 0x6c, 0x49, 0x64, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x63, 0x65, 0x6c, 0x6c, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x67, 0x70,
	0x73, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x08, 0x20, 0x02, 0x28, 0x05, 0x52, 0x09, 0x67,
	0x70, 0x73, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x62, 0x54, 0x69,
	0x6d, 0x65, 0x18, 0x09, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x06, 0x73, 0x62, 0x54, 0x69, 0x6d, 0x65,
	0x22, 0x9d, 0x01, 0x0a, 0x0e, 0x53, 0x6e, 0x73, 0x4c, 0x62, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x61, 0x73, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63,
	0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x6f,
	0x6e, 0x74, 0x61, 0x63, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x34, 0x0a, 0x0b, 0x63, 0x6f,
	0x6e, 0x74, 0x61, 0x63, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x12, 0x2e, 0x53, 0x6e, 0x73, 0x4c, 0x62, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x4c, 0x69, 0x73, 0x74,
	0x42, 0x0c, 0x5a, 0x0a, 0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_SnsLbs_proto_rawDescOnce sync.Once
	file_SnsLbs_proto_rawDescData = file_SnsLbs_proto_rawDesc
)

func file_SnsLbs_proto_rawDescGZIP() []byte {
	file_SnsLbs_proto_rawDescOnce.Do(func() {
		file_SnsLbs_proto_rawDescData = protoimpl.X.CompressGZIP(file_SnsLbs_proto_rawDescData)
	})
	return file_SnsLbs_proto_rawDescData
}

var file_SnsLbs_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_SnsLbs_proto_goTypes = []interface{}{
	(*SnsLbsRequest)(nil),     // 0: SnsLbsRequest
	(*SnsLbsResponse)(nil),    // 1: SnsLbsResponse
	(*BaseRequest)(nil),       // 2: BaseRequest
	(*BaseResponse)(nil),      // 3: BaseResponse
	(*SnsLbsContactInfo)(nil), // 4: SnsLbsContactInfo
}
var file_SnsLbs_proto_depIdxs = []int32{
	2, // 0: SnsLbsRequest.baseRequest:type_name -> BaseRequest
	3, // 1: SnsLbsResponse.baseResponse:type_name -> BaseResponse
	4, // 2: SnsLbsResponse.contactList:type_name -> SnsLbsContactInfo
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_SnsLbs_proto_init() }
func file_SnsLbs_proto_init() {
	if File_SnsLbs_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	file_MicroSnsBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SnsLbs_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsLbsRequest); i {
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
		file_SnsLbs_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsLbsResponse); i {
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
			RawDescriptor: file_SnsLbs_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SnsLbs_proto_goTypes,
		DependencyIndexes: file_SnsLbs_proto_depIdxs,
		MessageInfos:      file_SnsLbs_proto_msgTypes,
	}.Build()
	File_SnsLbs_proto = out.File
	file_SnsLbs_proto_rawDesc = nil
	file_SnsLbs_proto_goTypes = nil
	file_SnsLbs_proto_depIdxs = nil
}
