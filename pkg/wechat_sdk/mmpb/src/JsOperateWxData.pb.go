// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: JsOperateWxData.proto

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

type JsOperateWxDataVipRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest *BaseRequest     `protobuf:"bytes,1,opt,name=baseRequest" json:"baseRequest,omitempty"`
	Appid       *string          `protobuf:"bytes,2,opt,name=appid" json:"appid,omitempty"`
	Data        []byte           `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
	GrantScope  *string          `protobuf:"bytes,4,opt,name=grantScope" json:"grantScope,omitempty"`
	Opt         *int32           `protobuf:"varint,5,opt,name=opt" json:"opt,omitempty"`
	VersionType *int32           `protobuf:"varint,6,opt,name=versionType" json:"versionType,omitempty"`
	ExtInfo     *WxaExternalInfo `protobuf:"bytes,7,opt,name=extInfo" json:"extInfo,omitempty"`
	AvatarId    *int32           `protobuf:"varint,8,opt,name=avatarId" json:"avatarId,omitempty"`
}

func (x *JsOperateWxDataVipRequest) Reset() {
	*x = JsOperateWxDataVipRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_JsOperateWxData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JsOperateWxDataVipRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JsOperateWxDataVipRequest) ProtoMessage() {}

func (x *JsOperateWxDataVipRequest) ProtoReflect() protoreflect.Message {
	mi := &file_JsOperateWxData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JsOperateWxDataVipRequest.ProtoReflect.Descriptor instead.
func (*JsOperateWxDataVipRequest) Descriptor() ([]byte, []int) {
	return file_JsOperateWxData_proto_rawDescGZIP(), []int{0}
}

func (x *JsOperateWxDataVipRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *JsOperateWxDataVipRequest) GetAppid() string {
	if x != nil && x.Appid != nil {
		return *x.Appid
	}
	return ""
}

func (x *JsOperateWxDataVipRequest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *JsOperateWxDataVipRequest) GetGrantScope() string {
	if x != nil && x.GrantScope != nil {
		return *x.GrantScope
	}
	return ""
}

func (x *JsOperateWxDataVipRequest) GetOpt() int32 {
	if x != nil && x.Opt != nil {
		return *x.Opt
	}
	return 0
}

func (x *JsOperateWxDataVipRequest) GetVersionType() int32 {
	if x != nil && x.VersionType != nil {
		return *x.VersionType
	}
	return 0
}

func (x *JsOperateWxDataVipRequest) GetExtInfo() *WxaExternalInfo {
	if x != nil {
		return x.ExtInfo
	}
	return nil
}

func (x *JsOperateWxDataVipRequest) GetAvatarId() int32 {
	if x != nil && x.AvatarId != nil {
		return *x.AvatarId
	}
	return 0
}

type JsOperateWxDataVipResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse      *BaseResponse      `protobuf:"bytes,1,opt,name=baseResponse" json:"baseResponse,omitempty"`
	JsApiBaseResponse *JsApiBaseResponse `protobuf:"bytes,2,opt,name=jsApiBaseResponse" json:"jsApiBaseResponse,omitempty"`
	Data              []byte             `protobuf:"bytes,3,opt,name=data" json:"data,omitempty"`
	Scope             *ScopeInfo         `protobuf:"bytes,4,opt,name=scope" json:"scope,omitempty"`
	AppName           *string            `protobuf:"bytes,5,opt,name=appName" json:"appName,omitempty"`
	AppIconUrl        *string            `protobuf:"bytes,6,opt,name=appIconUrl" json:"appIconUrl,omitempty"`
	DebugInfo         *string            `protobuf:"bytes,7,opt,name=debugInfo" json:"debugInfo,omitempty"`
	NeedHoldLongconn  *bool              `protobuf:"varint,8,opt,name=needHoldLongconn" json:"needHoldLongconn,omitempty"`
	CancelWording     *string            `protobuf:"bytes,9,opt,name=cancelWording" json:"cancelWording,omitempty"`
	AllowWording      *string            `protobuf:"bytes,10,opt,name=allowWording" json:"allowWording,omitempty"`
	ApplyWording      *string            `protobuf:"bytes,11,opt,name=applyWording" json:"applyWording,omitempty"`
	AvatarInfo        *AvatarInfoList    `protobuf:"bytes,12,opt,name=avatarInfo" json:"avatarInfo,omitempty"`
}

func (x *JsOperateWxDataVipResponse) Reset() {
	*x = JsOperateWxDataVipResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_JsOperateWxData_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *JsOperateWxDataVipResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JsOperateWxDataVipResponse) ProtoMessage() {}

func (x *JsOperateWxDataVipResponse) ProtoReflect() protoreflect.Message {
	mi := &file_JsOperateWxData_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JsOperateWxDataVipResponse.ProtoReflect.Descriptor instead.
func (*JsOperateWxDataVipResponse) Descriptor() ([]byte, []int) {
	return file_JsOperateWxData_proto_rawDescGZIP(), []int{1}
}

func (x *JsOperateWxDataVipResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *JsOperateWxDataVipResponse) GetJsApiBaseResponse() *JsApiBaseResponse {
	if x != nil {
		return x.JsApiBaseResponse
	}
	return nil
}

func (x *JsOperateWxDataVipResponse) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *JsOperateWxDataVipResponse) GetScope() *ScopeInfo {
	if x != nil {
		return x.Scope
	}
	return nil
}

func (x *JsOperateWxDataVipResponse) GetAppName() string {
	if x != nil && x.AppName != nil {
		return *x.AppName
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetAppIconUrl() string {
	if x != nil && x.AppIconUrl != nil {
		return *x.AppIconUrl
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetDebugInfo() string {
	if x != nil && x.DebugInfo != nil {
		return *x.DebugInfo
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetNeedHoldLongconn() bool {
	if x != nil && x.NeedHoldLongconn != nil {
		return *x.NeedHoldLongconn
	}
	return false
}

func (x *JsOperateWxDataVipResponse) GetCancelWording() string {
	if x != nil && x.CancelWording != nil {
		return *x.CancelWording
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetAllowWording() string {
	if x != nil && x.AllowWording != nil {
		return *x.AllowWording
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetApplyWording() string {
	if x != nil && x.ApplyWording != nil {
		return *x.ApplyWording
	}
	return ""
}

func (x *JsOperateWxDataVipResponse) GetAvatarInfo() *AvatarInfoList {
	if x != nil {
		return x.AvatarInfo
	}
	return nil
}

var File_JsOperateWxData_proto protoreflect.FileDescriptor

var file_JsOperateWxData_proto_rawDesc = []byte{
	0x0a, 0x15, 0x4a, 0x73, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x65, 0x57, 0x78, 0x44, 0x61, 0x74,
	0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x4d, 0x73,
	0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x91, 0x02, 0x0a, 0x19,
	0x4a, 0x73, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x65, 0x57, 0x78, 0x44, 0x61, 0x74, 0x61, 0x56,
	0x69, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x62, 0x61, 0x73,
	0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c,
	0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x62, 0x61,
	0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x70, 0x70,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x61, 0x70, 0x70, 0x69, 0x64, 0x12,
	0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x12, 0x1e, 0x0a, 0x0a, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x53, 0x63, 0x6f, 0x70,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x53, 0x63,
	0x6f, 0x70, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6f, 0x70, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x03, 0x6f, 0x70, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x54, 0x79, 0x70, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x2a, 0x0a, 0x07, 0x65, 0x78, 0x74, 0x49, 0x6e,
	0x66, 0x6f, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x57, 0x78, 0x61, 0x45, 0x78,
	0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x07, 0x65, 0x78, 0x74, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x64, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x64, 0x22,
	0xea, 0x03, 0x0a, 0x1a, 0x4a, 0x73, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x65, 0x57, 0x78, 0x44,
	0x61, 0x74, 0x61, 0x56, 0x69, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x31,
	0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x40, 0x0a, 0x11, 0x6a, 0x73, 0x41, 0x70, 0x69, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x4a,
	0x73, 0x41, 0x70, 0x69, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x52, 0x11, 0x6a, 0x73, 0x41, 0x70, 0x69, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x20, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x70, 0x70,
	0x4e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x70, 0x70, 0x4e,
	0x61, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x70, 0x70, 0x49, 0x63, 0x6f, 0x6e, 0x55, 0x72,
	0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x70, 0x70, 0x49, 0x63, 0x6f, 0x6e,
	0x55, 0x72, 0x6c, 0x12, 0x1c, 0x0a, 0x09, 0x64, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x64, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x2a, 0x0a, 0x10, 0x6e, 0x65, 0x65, 0x64, 0x48, 0x6f, 0x6c, 0x64, 0x4c, 0x6f, 0x6e,
	0x67, 0x63, 0x6f, 0x6e, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x6e, 0x65, 0x65,
	0x64, 0x48, 0x6f, 0x6c, 0x64, 0x4c, 0x6f, 0x6e, 0x67, 0x63, 0x6f, 0x6e, 0x6e, 0x12, 0x24, 0x0a,
	0x0d, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x57, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x57, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x67, 0x12, 0x22, 0x0a, 0x0c, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x57, 0x6f, 0x72, 0x64,
	0x69, 0x6e, 0x67, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61, 0x6c, 0x6c, 0x6f, 0x77,
	0x57, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x12, 0x22, 0x0a, 0x0c, 0x61, 0x70, 0x70, 0x6c, 0x79,
	0x57, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61,
	0x70, 0x70, 0x6c, 0x79, 0x57, 0x6f, 0x72, 0x64, 0x69, 0x6e, 0x67, 0x12, 0x2f, 0x0a, 0x0a, 0x61,
	0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74,
	0x52, 0x0a, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x0c, 0x5a, 0x0a,
	0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_JsOperateWxData_proto_rawDescOnce sync.Once
	file_JsOperateWxData_proto_rawDescData = file_JsOperateWxData_proto_rawDesc
)

func file_JsOperateWxData_proto_rawDescGZIP() []byte {
	file_JsOperateWxData_proto_rawDescOnce.Do(func() {
		file_JsOperateWxData_proto_rawDescData = protoimpl.X.CompressGZIP(file_JsOperateWxData_proto_rawDescData)
	})
	return file_JsOperateWxData_proto_rawDescData
}

var file_JsOperateWxData_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_JsOperateWxData_proto_goTypes = []interface{}{
	(*JsOperateWxDataVipRequest)(nil),  // 0: JsOperateWxDataVipRequest
	(*JsOperateWxDataVipResponse)(nil), // 1: JsOperateWxDataVipResponse
	(*BaseRequest)(nil),                // 2: BaseRequest
	(*WxaExternalInfo)(nil),            // 3: WxaExternalInfo
	(*BaseResponse)(nil),               // 4: BaseResponse
	(*JsApiBaseResponse)(nil),          // 5: JsApiBaseResponse
	(*ScopeInfo)(nil),                  // 6: ScopeInfo
	(*AvatarInfoList)(nil),             // 7: AvatarInfoList
}
var file_JsOperateWxData_proto_depIdxs = []int32{
	2, // 0: JsOperateWxDataVipRequest.baseRequest:type_name -> BaseRequest
	3, // 1: JsOperateWxDataVipRequest.extInfo:type_name -> WxaExternalInfo
	4, // 2: JsOperateWxDataVipResponse.baseResponse:type_name -> BaseResponse
	5, // 3: JsOperateWxDataVipResponse.jsApiBaseResponse:type_name -> JsApiBaseResponse
	6, // 4: JsOperateWxDataVipResponse.scope:type_name -> ScopeInfo
	7, // 5: JsOperateWxDataVipResponse.avatarInfo:type_name -> AvatarInfoList
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_JsOperateWxData_proto_init() }
func file_JsOperateWxData_proto_init() {
	if File_JsOperateWxData_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_JsOperateWxData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JsOperateWxDataVipRequest); i {
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
		file_JsOperateWxData_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*JsOperateWxDataVipResponse); i {
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
			RawDescriptor: file_JsOperateWxData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_JsOperateWxData_proto_goTypes,
		DependencyIndexes: file_JsOperateWxData_proto_depIdxs,
		MessageInfos:      file_JsOperateWxData_proto_msgTypes,
	}.Build()
	File_JsOperateWxData_proto = out.File
	file_JsOperateWxData_proto_rawDesc = nil
	file_JsOperateWxData_proto_goTypes = nil
	file_JsOperateWxData_proto_depIdxs = nil
}