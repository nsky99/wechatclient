// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: DelChatRoomMember.proto

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

type DelChatRoomMemberRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest  *BaseRequest    `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	MemberCount  *uint32         `protobuf:"varint,2,req,name=memberCount" json:"memberCount,omitempty"`
	MemberList   []*DelMemberReq `protobuf:"bytes,3,rep,name=memberList" json:"memberList,omitempty"`
	ChatRoomName *string         `protobuf:"bytes,4,opt,name=chatRoomName" json:"chatRoomName,omitempty"`
	Scene        *uint32         `protobuf:"varint,5,opt,name=scene" json:"scene,omitempty"`
}

func (x *DelChatRoomMemberRequest) Reset() {
	*x = DelChatRoomMemberRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DelChatRoomMember_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DelChatRoomMemberRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DelChatRoomMemberRequest) ProtoMessage() {}

func (x *DelChatRoomMemberRequest) ProtoReflect() protoreflect.Message {
	mi := &file_DelChatRoomMember_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DelChatRoomMemberRequest.ProtoReflect.Descriptor instead.
func (*DelChatRoomMemberRequest) Descriptor() ([]byte, []int) {
	return file_DelChatRoomMember_proto_rawDescGZIP(), []int{0}
}

func (x *DelChatRoomMemberRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *DelChatRoomMemberRequest) GetMemberCount() uint32 {
	if x != nil && x.MemberCount != nil {
		return *x.MemberCount
	}
	return 0
}

func (x *DelChatRoomMemberRequest) GetMemberList() []*DelMemberReq {
	if x != nil {
		return x.MemberList
	}
	return nil
}

func (x *DelChatRoomMemberRequest) GetChatRoomName() string {
	if x != nil && x.ChatRoomName != nil {
		return *x.ChatRoomName
	}
	return ""
}

func (x *DelChatRoomMemberRequest) GetScene() uint32 {
	if x != nil && x.Scene != nil {
		return *x.Scene
	}
	return 0
}

type DelChatRoomMemberResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse *BaseResponse    `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	MemberCount  *uint32          `protobuf:"varint,2,req,name=memberCount" json:"memberCount,omitempty"`
	MemberList   []*DelMemberResp `protobuf:"bytes,3,rep,name=memberList" json:"memberList,omitempty"`
}

func (x *DelChatRoomMemberResponse) Reset() {
	*x = DelChatRoomMemberResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DelChatRoomMember_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DelChatRoomMemberResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DelChatRoomMemberResponse) ProtoMessage() {}

func (x *DelChatRoomMemberResponse) ProtoReflect() protoreflect.Message {
	mi := &file_DelChatRoomMember_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DelChatRoomMemberResponse.ProtoReflect.Descriptor instead.
func (*DelChatRoomMemberResponse) Descriptor() ([]byte, []int) {
	return file_DelChatRoomMember_proto_rawDescGZIP(), []int{1}
}

func (x *DelChatRoomMemberResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *DelChatRoomMemberResponse) GetMemberCount() uint32 {
	if x != nil && x.MemberCount != nil {
		return *x.MemberCount
	}
	return 0
}

func (x *DelChatRoomMemberResponse) GetMemberList() []*DelMemberResp {
	if x != nil {
		return x.MemberList
	}
	return nil
}

var File_DelChatRoomMember_proto protoreflect.FileDescriptor

var file_DelChatRoomMember_proto_rawDesc = []byte{
	0x0a, 0x17, 0x44, 0x65, 0x6c, 0x43, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x4d, 0x65, 0x6d,
	0x62, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f,
	0x4d, 0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13, 0x4d,
	0x69, 0x63, 0x72, 0x6f, 0x52, 0x6f, 0x6f, 0x6d, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xd5, 0x01, 0x0a, 0x18, 0x44, 0x65, 0x6c, 0x43, 0x68, 0x61, 0x74, 0x52, 0x6f,
	0x6f, 0x6d, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x2e, 0x0a, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01,
	0x20, 0x02, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x52, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x20, 0x0a, 0x0b, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x0d, 0x52, 0x0b, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x2d, 0x0a, 0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x44, 0x65, 0x6c, 0x4d, 0x65, 0x6d, 0x62, 0x65,
	0x72, 0x52, 0x65, 0x71, 0x52, 0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x22, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x4e, 0x61, 0x6d, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d,
	0x4e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x22, 0xa0, 0x01, 0x0a, 0x19, 0x44,
	0x65, 0x6c, 0x43, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d,
	0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62,
	0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x6d,
	0x65, 0x6d, 0x62, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d,
	0x52, 0x0b, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e, 0x0a,
	0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x0e, 0x2e, 0x44, 0x65, 0x6c, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x65, 0x73,
	0x70, 0x52, 0x0a, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x0c, 0x5a,
	0x0a, 0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_DelChatRoomMember_proto_rawDescOnce sync.Once
	file_DelChatRoomMember_proto_rawDescData = file_DelChatRoomMember_proto_rawDesc
)

func file_DelChatRoomMember_proto_rawDescGZIP() []byte {
	file_DelChatRoomMember_proto_rawDescOnce.Do(func() {
		file_DelChatRoomMember_proto_rawDescData = protoimpl.X.CompressGZIP(file_DelChatRoomMember_proto_rawDescData)
	})
	return file_DelChatRoomMember_proto_rawDescData
}

var file_DelChatRoomMember_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_DelChatRoomMember_proto_goTypes = []interface{}{
	(*DelChatRoomMemberRequest)(nil),  // 0: DelChatRoomMemberRequest
	(*DelChatRoomMemberResponse)(nil), // 1: DelChatRoomMemberResponse
	(*BaseRequest)(nil),               // 2: BaseRequest
	(*DelMemberReq)(nil),              // 3: DelMemberReq
	(*BaseResponse)(nil),              // 4: BaseResponse
	(*DelMemberResp)(nil),             // 5: DelMemberResp
}
var file_DelChatRoomMember_proto_depIdxs = []int32{
	2, // 0: DelChatRoomMemberRequest.baseRequest:type_name -> BaseRequest
	3, // 1: DelChatRoomMemberRequest.memberList:type_name -> DelMemberReq
	4, // 2: DelChatRoomMemberResponse.baseResponse:type_name -> BaseResponse
	5, // 3: DelChatRoomMemberResponse.memberList:type_name -> DelMemberResp
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_DelChatRoomMember_proto_init() }
func file_DelChatRoomMember_proto_init() {
	if File_DelChatRoomMember_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	file_MicroRoomBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_DelChatRoomMember_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DelChatRoomMemberRequest); i {
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
		file_DelChatRoomMember_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DelChatRoomMemberResponse); i {
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
			RawDescriptor: file_DelChatRoomMember_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DelChatRoomMember_proto_goTypes,
		DependencyIndexes: file_DelChatRoomMember_proto_depIdxs,
		MessageInfos:      file_DelChatRoomMember_proto_msgTypes,
	}.Build()
	File_DelChatRoomMember_proto = out.File
	file_DelChatRoomMember_proto_rawDesc = nil
	file_DelChatRoomMember_proto_goTypes = nil
	file_DelChatRoomMember_proto_depIdxs = nil
}