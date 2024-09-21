// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: CheckLoginQRCode.proto

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

type LoginQRCodeNotifyPkg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NotifyData *SKBuiltinBufferT `protobuf:"bytes,1,req,name=notifyData" json:"notifyData,omitempty"`
	Opcode     *uint32           `protobuf:"varint,2,req,name=opcode" json:"opcode,omitempty"`
}

func (x *LoginQRCodeNotifyPkg) Reset() {
	*x = LoginQRCodeNotifyPkg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CheckLoginQRCode_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginQRCodeNotifyPkg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginQRCodeNotifyPkg) ProtoMessage() {}

func (x *LoginQRCodeNotifyPkg) ProtoReflect() protoreflect.Message {
	mi := &file_CheckLoginQRCode_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginQRCodeNotifyPkg.ProtoReflect.Descriptor instead.
func (*LoginQRCodeNotifyPkg) Descriptor() ([]byte, []int) {
	return file_CheckLoginQRCode_proto_rawDescGZIP(), []int{0}
}

func (x *LoginQRCodeNotifyPkg) GetNotifyData() *SKBuiltinBufferT {
	if x != nil {
		return x.NotifyData
	}
	return nil
}

func (x *LoginQRCodeNotifyPkg) GetOpcode() uint32 {
	if x != nil && x.Opcode != nil {
		return *x.Opcode
	}
	return 0
}

type CheckLoginQRCodeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest    *BaseRequest      `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	RandomEncryKey *SKBuiltinBufferT `protobuf:"bytes,2,req,name=randomEncryKey" json:"randomEncryKey,omitempty"`
	Uuid           *string           `protobuf:"bytes,3,opt,name=uuid" json:"uuid,omitempty"`
	Timestamp      *uint32           `protobuf:"varint,4,req,name=timestamp" json:"timestamp,omitempty"`
	Opcode         *uint32           `protobuf:"varint,5,opt,name=opcode" json:"opcode,omitempty"`
}

func (x *CheckLoginQRCodeRequest) Reset() {
	*x = CheckLoginQRCodeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CheckLoginQRCode_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CheckLoginQRCodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CheckLoginQRCodeRequest) ProtoMessage() {}

func (x *CheckLoginQRCodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_CheckLoginQRCode_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CheckLoginQRCodeRequest.ProtoReflect.Descriptor instead.
func (*CheckLoginQRCodeRequest) Descriptor() ([]byte, []int) {
	return file_CheckLoginQRCode_proto_rawDescGZIP(), []int{1}
}

func (x *CheckLoginQRCodeRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *CheckLoginQRCodeRequest) GetRandomEncryKey() *SKBuiltinBufferT {
	if x != nil {
		return x.RandomEncryKey
	}
	return nil
}

func (x *CheckLoginQRCodeRequest) GetUuid() string {
	if x != nil && x.Uuid != nil {
		return *x.Uuid
	}
	return ""
}

func (x *CheckLoginQRCodeRequest) GetTimestamp() uint32 {
	if x != nil && x.Timestamp != nil {
		return *x.Timestamp
	}
	return 0
}

func (x *CheckLoginQRCodeRequest) GetOpcode() uint32 {
	if x != nil && x.Opcode != nil {
		return *x.Opcode
	}
	return 0
}

type CheckLoginQRCodeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse *BaseResponse         `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	NotifyPkg    *LoginQRCodeNotifyPkg `protobuf:"bytes,3,opt,name=notifyPkg" json:"notifyPkg,omitempty"`
}

func (x *CheckLoginQRCodeResponse) Reset() {
	*x = CheckLoginQRCodeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CheckLoginQRCode_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CheckLoginQRCodeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CheckLoginQRCodeResponse) ProtoMessage() {}

func (x *CheckLoginQRCodeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_CheckLoginQRCode_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CheckLoginQRCodeResponse.ProtoReflect.Descriptor instead.
func (*CheckLoginQRCodeResponse) Descriptor() ([]byte, []int) {
	return file_CheckLoginQRCode_proto_rawDescGZIP(), []int{2}
}

func (x *CheckLoginQRCodeResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *CheckLoginQRCodeResponse) GetNotifyPkg() *LoginQRCodeNotifyPkg {
	if x != nil {
		return x.NotifyPkg
	}
	return nil
}

type LoginQRCodeNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uuid                    *string `protobuf:"bytes,1,opt,name=uuid" json:"uuid,omitempty"`
	Status                  *uint32 `protobuf:"varint,2,req,name=status" json:"status,omitempty"`
	Username                *string `protobuf:"bytes,3,opt,name=username" json:"username,omitempty"`
	Pwd                     *string `protobuf:"bytes,4,opt,name=pwd" json:"pwd,omitempty"`
	HeadImgURL              *string `protobuf:"bytes,5,opt,name=headImgURL" json:"headImgURL,omitempty"`
	PushLoginURLExpiredTime *uint32 `protobuf:"varint,6,opt,name=pushLoginURLExpiredTime" json:"pushLoginURLExpiredTime,omitempty"`
	Nickname                *string `protobuf:"bytes,7,opt,name=nickname" json:"nickname,omitempty"`
	ExpiredTime             *uint32 `protobuf:"varint,8,opt,name=expiredTime" json:"expiredTime,omitempty"`
	PairWaitTip             *string `protobuf:"bytes,9,opt,name=pairWaitTip" json:"pairWaitTip,omitempty"`
	AuthorClientVersion     *uint32 `protobuf:"varint,10,opt,name=authorClientVersion" json:"authorClientVersion,omitempty"`
	AuthorDeviceType        *string `protobuf:"bytes,11,opt,name=authorDeviceType" json:"authorDeviceType,omitempty"`
}

func (x *LoginQRCodeNotify) Reset() {
	*x = LoginQRCodeNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CheckLoginQRCode_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoginQRCodeNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginQRCodeNotify) ProtoMessage() {}

func (x *LoginQRCodeNotify) ProtoReflect() protoreflect.Message {
	mi := &file_CheckLoginQRCode_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginQRCodeNotify.ProtoReflect.Descriptor instead.
func (*LoginQRCodeNotify) Descriptor() ([]byte, []int) {
	return file_CheckLoginQRCode_proto_rawDescGZIP(), []int{3}
}

func (x *LoginQRCodeNotify) GetUuid() string {
	if x != nil && x.Uuid != nil {
		return *x.Uuid
	}
	return ""
}

func (x *LoginQRCodeNotify) GetStatus() uint32 {
	if x != nil && x.Status != nil {
		return *x.Status
	}
	return 0
}

func (x *LoginQRCodeNotify) GetUsername() string {
	if x != nil && x.Username != nil {
		return *x.Username
	}
	return ""
}

func (x *LoginQRCodeNotify) GetPwd() string {
	if x != nil && x.Pwd != nil {
		return *x.Pwd
	}
	return ""
}

func (x *LoginQRCodeNotify) GetHeadImgURL() string {
	if x != nil && x.HeadImgURL != nil {
		return *x.HeadImgURL
	}
	return ""
}

func (x *LoginQRCodeNotify) GetPushLoginURLExpiredTime() uint32 {
	if x != nil && x.PushLoginURLExpiredTime != nil {
		return *x.PushLoginURLExpiredTime
	}
	return 0
}

func (x *LoginQRCodeNotify) GetNickname() string {
	if x != nil && x.Nickname != nil {
		return *x.Nickname
	}
	return ""
}

func (x *LoginQRCodeNotify) GetExpiredTime() uint32 {
	if x != nil && x.ExpiredTime != nil {
		return *x.ExpiredTime
	}
	return 0
}

func (x *LoginQRCodeNotify) GetPairWaitTip() string {
	if x != nil && x.PairWaitTip != nil {
		return *x.PairWaitTip
	}
	return ""
}

func (x *LoginQRCodeNotify) GetAuthorClientVersion() uint32 {
	if x != nil && x.AuthorClientVersion != nil {
		return *x.AuthorClientVersion
	}
	return 0
}

func (x *LoginQRCodeNotify) GetAuthorDeviceType() string {
	if x != nil && x.AuthorDeviceType != nil {
		return *x.AuthorDeviceType
	}
	return ""
}

var File_CheckLoginQRCode_proto protoreflect.FileDescriptor

var file_CheckLoginQRCode_proto_rawDesc = []byte{
	0x0a, 0x16, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x51, 0x52, 0x43, 0x6f,
	0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x4d,
	0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x62, 0x0a, 0x14,
	0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x51, 0x52, 0x43, 0x6f, 0x64, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x50, 0x6b, 0x67, 0x12, 0x32, 0x0a, 0x0a, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x44, 0x61,
	0x74, 0x61, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69,
	0x6c, 0x74, 0x69, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f, 0x74, 0x52, 0x0a, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x44, 0x61, 0x74, 0x61, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x70, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0d, 0x52, 0x06, 0x6f, 0x70, 0x63, 0x6f, 0x64, 0x65,
	0x22, 0xcf, 0x01, 0x0a, 0x17, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x51,
	0x52, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b,
	0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x02, 0x28,
	0x0b, 0x32, 0x0c, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52,
	0x0b, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3a, 0x0a, 0x0e,
	0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x4b, 0x65, 0x79, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e,
	0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f, 0x74, 0x52, 0x0e, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x4b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x04, 0x20, 0x02, 0x28, 0x0d, 0x52,
	0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x70,
	0x63, 0x6f, 0x64, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x6f, 0x70, 0x63, 0x6f,
	0x64, 0x65, 0x22, 0x82, 0x01, 0x0a, 0x18, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x51, 0x52, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18,
	0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x33, 0x0a, 0x09, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x50, 0x6b, 0x67, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x51, 0x52, 0x43,
	0x6f, 0x64, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x50, 0x6b, 0x67, 0x52, 0x09, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x50, 0x6b, 0x67, 0x22, 0x85, 0x03, 0x0a, 0x11, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x51, 0x52, 0x43, 0x6f, 0x64, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x12, 0x0a,
	0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69,
	0x64, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x02, 0x28,
	0x0d, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65,
	0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65,
	0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x77, 0x64, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x70, 0x77, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x68, 0x65, 0x61, 0x64, 0x49,
	0x6d, 0x67, 0x55, 0x52, 0x4c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x68, 0x65, 0x61,
	0x64, 0x49, 0x6d, 0x67, 0x55, 0x52, 0x4c, 0x12, 0x38, 0x0a, 0x17, 0x70, 0x75, 0x73, 0x68, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x55, 0x52, 0x4c, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x54, 0x69,
	0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x17, 0x70, 0x75, 0x73, 0x68, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x55, 0x52, 0x4c, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x1a, 0x0a, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a,
	0x0b, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x20, 0x0a, 0x0b, 0x70, 0x61, 0x69, 0x72, 0x57, 0x61, 0x69, 0x74, 0x54, 0x69, 0x70, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x61, 0x69, 0x72, 0x57, 0x61, 0x69, 0x74, 0x54, 0x69,
	0x70, 0x12, 0x30, 0x0a, 0x13, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13,
	0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x2a, 0x0a, 0x10, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x44, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x42,
	0x0c, 0x5a, 0x0a, 0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_CheckLoginQRCode_proto_rawDescOnce sync.Once
	file_CheckLoginQRCode_proto_rawDescData = file_CheckLoginQRCode_proto_rawDesc
)

func file_CheckLoginQRCode_proto_rawDescGZIP() []byte {
	file_CheckLoginQRCode_proto_rawDescOnce.Do(func() {
		file_CheckLoginQRCode_proto_rawDescData = protoimpl.X.CompressGZIP(file_CheckLoginQRCode_proto_rawDescData)
	})
	return file_CheckLoginQRCode_proto_rawDescData
}

var file_CheckLoginQRCode_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_CheckLoginQRCode_proto_goTypes = []interface{}{
	(*LoginQRCodeNotifyPkg)(nil),     // 0: LoginQRCodeNotifyPkg
	(*CheckLoginQRCodeRequest)(nil),  // 1: CheckLoginQRCodeRequest
	(*CheckLoginQRCodeResponse)(nil), // 2: CheckLoginQRCodeResponse
	(*LoginQRCodeNotify)(nil),        // 3: LoginQRCodeNotify
	(*SKBuiltinBufferT)(nil),         // 4: SKBuiltinBuffer_t
	(*BaseRequest)(nil),              // 5: BaseRequest
	(*BaseResponse)(nil),             // 6: BaseResponse
}
var file_CheckLoginQRCode_proto_depIdxs = []int32{
	4, // 0: LoginQRCodeNotifyPkg.notifyData:type_name -> SKBuiltinBuffer_t
	5, // 1: CheckLoginQRCodeRequest.baseRequest:type_name -> BaseRequest
	4, // 2: CheckLoginQRCodeRequest.randomEncryKey:type_name -> SKBuiltinBuffer_t
	6, // 3: CheckLoginQRCodeResponse.baseResponse:type_name -> BaseResponse
	0, // 4: CheckLoginQRCodeResponse.notifyPkg:type_name -> LoginQRCodeNotifyPkg
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_CheckLoginQRCode_proto_init() }
func file_CheckLoginQRCode_proto_init() {
	if File_CheckLoginQRCode_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_CheckLoginQRCode_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginQRCodeNotifyPkg); i {
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
		file_CheckLoginQRCode_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CheckLoginQRCodeRequest); i {
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
		file_CheckLoginQRCode_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CheckLoginQRCodeResponse); i {
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
		file_CheckLoginQRCode_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoginQRCodeNotify); i {
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
			RawDescriptor: file_CheckLoginQRCode_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CheckLoginQRCode_proto_goTypes,
		DependencyIndexes: file_CheckLoginQRCode_proto_depIdxs,
		MessageInfos:      file_CheckLoginQRCode_proto_msgTypes,
	}.Build()
	File_CheckLoginQRCode_proto = out.File
	file_CheckLoginQRCode_proto_rawDesc = nil
	file_CheckLoginQRCode_proto_goTypes = nil
	file_CheckLoginQRCode_proto_depIdxs = nil
}