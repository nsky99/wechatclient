// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: GetChatRoomInfoDetail.proto

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

type GetChatRoomInfoDetailRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest  *BaseRequest `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	ChatRoomName *string      `protobuf:"bytes,2,opt,name=chatRoomName" json:"chatRoomName,omitempty"`
}

func (x *GetChatRoomInfoDetailRequest) Reset() {
	*x = GetChatRoomInfoDetailRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetChatRoomInfoDetail_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetChatRoomInfoDetailRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetChatRoomInfoDetailRequest) ProtoMessage() {}

func (x *GetChatRoomInfoDetailRequest) ProtoReflect() protoreflect.Message {
	mi := &file_GetChatRoomInfoDetail_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetChatRoomInfoDetailRequest.ProtoReflect.Descriptor instead.
func (*GetChatRoomInfoDetailRequest) Descriptor() ([]byte, []int) {
	return file_GetChatRoomInfoDetail_proto_rawDescGZIP(), []int{0}
}

func (x *GetChatRoomInfoDetailRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *GetChatRoomInfoDetailRequest) GetChatRoomName() string {
	if x != nil && x.ChatRoomName != nil {
		return *x.ChatRoomName
	}
	return ""
}

type GetChatRoomInfoDetailResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse            *BaseResponse `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	Announcement            *string       `protobuf:"bytes,2,opt,name=announcement" json:"announcement,omitempty"`
	ChatRoomInfoVersion     *uint32       `protobuf:"varint,3,opt,name=chatRoomInfoVersion" json:"chatRoomInfoVersion,omitempty"`
	AnnouncementEditor      *string       `protobuf:"bytes,4,opt,name=announcementEditor" json:"announcementEditor,omitempty"`
	AnnouncementPublishTime *uint32       `protobuf:"varint,5,opt,name=announcementPublishTime" json:"announcementPublishTime,omitempty"`
}

func (x *GetChatRoomInfoDetailResponse) Reset() {
	*x = GetChatRoomInfoDetailResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetChatRoomInfoDetail_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetChatRoomInfoDetailResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetChatRoomInfoDetailResponse) ProtoMessage() {}

func (x *GetChatRoomInfoDetailResponse) ProtoReflect() protoreflect.Message {
	mi := &file_GetChatRoomInfoDetail_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetChatRoomInfoDetailResponse.ProtoReflect.Descriptor instead.
func (*GetChatRoomInfoDetailResponse) Descriptor() ([]byte, []int) {
	return file_GetChatRoomInfoDetail_proto_rawDescGZIP(), []int{1}
}

func (x *GetChatRoomInfoDetailResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *GetChatRoomInfoDetailResponse) GetAnnouncement() string {
	if x != nil && x.Announcement != nil {
		return *x.Announcement
	}
	return ""
}

func (x *GetChatRoomInfoDetailResponse) GetChatRoomInfoVersion() uint32 {
	if x != nil && x.ChatRoomInfoVersion != nil {
		return *x.ChatRoomInfoVersion
	}
	return 0
}

func (x *GetChatRoomInfoDetailResponse) GetAnnouncementEditor() string {
	if x != nil && x.AnnouncementEditor != nil {
		return *x.AnnouncementEditor
	}
	return ""
}

func (x *GetChatRoomInfoDetailResponse) GetAnnouncementPublishTime() uint32 {
	if x != nil && x.AnnouncementPublishTime != nil {
		return *x.AnnouncementPublishTime
	}
	return 0
}

var File_GetChatRoomInfoDetail_proto protoreflect.FileDescriptor

var file_GetChatRoomInfoDetail_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x47, 0x65, 0x74, 0x43, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x49, 0x6e, 0x66,
	0x6f, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d,
	0x69, 0x63, 0x72, 0x6f, 0x4d, 0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x72, 0x0a, 0x1c, 0x47, 0x65, 0x74, 0x43, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d,
	0x49, 0x6e, 0x66, 0x6f, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x4e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f,
	0x6d, 0x4e, 0x61, 0x6d, 0x65, 0x22, 0x92, 0x02, 0x0a, 0x1d, 0x47, 0x65, 0x74, 0x43, 0x68, 0x61,
	0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d, 0x2e,
	0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61,
	0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x61, 0x6e,
	0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x30,
	0x0a, 0x13, 0x63, 0x68, 0x61, 0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13, 0x63, 0x68, 0x61,
	0x74, 0x52, 0x6f, 0x6f, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x2e, 0x0a, 0x12, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x45, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x61, 0x6e,
	0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x45, 0x64, 0x69, 0x74, 0x6f, 0x72,
	0x12, 0x38, 0x0a, 0x17, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x17, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x42, 0x0c, 0x5a, 0x0a, 0x2e, 0x3b,
	0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_GetChatRoomInfoDetail_proto_rawDescOnce sync.Once
	file_GetChatRoomInfoDetail_proto_rawDescData = file_GetChatRoomInfoDetail_proto_rawDesc
)

func file_GetChatRoomInfoDetail_proto_rawDescGZIP() []byte {
	file_GetChatRoomInfoDetail_proto_rawDescOnce.Do(func() {
		file_GetChatRoomInfoDetail_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetChatRoomInfoDetail_proto_rawDescData)
	})
	return file_GetChatRoomInfoDetail_proto_rawDescData
}

var file_GetChatRoomInfoDetail_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_GetChatRoomInfoDetail_proto_goTypes = []interface{}{
	(*GetChatRoomInfoDetailRequest)(nil),  // 0: GetChatRoomInfoDetailRequest
	(*GetChatRoomInfoDetailResponse)(nil), // 1: GetChatRoomInfoDetailResponse
	(*BaseRequest)(nil),                   // 2: BaseRequest
	(*BaseResponse)(nil),                  // 3: BaseResponse
}
var file_GetChatRoomInfoDetail_proto_depIdxs = []int32{
	2, // 0: GetChatRoomInfoDetailRequest.baseRequest:type_name -> BaseRequest
	3, // 1: GetChatRoomInfoDetailResponse.baseResponse:type_name -> BaseResponse
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_GetChatRoomInfoDetail_proto_init() }
func file_GetChatRoomInfoDetail_proto_init() {
	if File_GetChatRoomInfoDetail_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GetChatRoomInfoDetail_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetChatRoomInfoDetailRequest); i {
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
		file_GetChatRoomInfoDetail_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetChatRoomInfoDetailResponse); i {
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
			RawDescriptor: file_GetChatRoomInfoDetail_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetChatRoomInfoDetail_proto_goTypes,
		DependencyIndexes: file_GetChatRoomInfoDetail_proto_depIdxs,
		MessageInfos:      file_GetChatRoomInfoDetail_proto_msgTypes,
	}.Build()
	File_GetChatRoomInfoDetail_proto = out.File
	file_GetChatRoomInfoDetail_proto_rawDesc = nil
	file_GetChatRoomInfoDetail_proto_goTypes = nil
	file_GetChatRoomInfoDetail_proto_depIdxs = nil
}
