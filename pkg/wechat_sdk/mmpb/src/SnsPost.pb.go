// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v3.21.12
// source: SnsPost.proto

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

type SnsPostRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseRequest             *BaseRequest            `protobuf:"bytes,1,req,name=baseRequest" json:"baseRequest,omitempty"`
	ObjectDesc              *SKBuiltinBufferT       `protobuf:"bytes,2,req,name=objectDesc" json:"objectDesc,omitempty"`
	WithUserListCount       *uint32                 `protobuf:"varint,3,opt,name=withUserListCount" json:"withUserListCount,omitempty"`
	WithUserList            []*SKBuiltinStringT     `protobuf:"bytes,4,rep,name=withUserList" json:"withUserList,omitempty"`
	Privacy                 *uint32                 `protobuf:"varint,5,opt,name=privacy" json:"privacy,omitempty"`
	SyncFlag                *uint32                 `protobuf:"varint,6,opt,name=syncFlag" json:"syncFlag,omitempty"`
	ClientId                *string                 `protobuf:"bytes,7,opt,name=clientId" json:"clientId,omitempty"`
	PostBgImgType           *uint32                 `protobuf:"varint,8,opt,name=postBgImgType" json:"postBgImgType,omitempty"`
	GroupCount              *uint32                 `protobuf:"varint,9,opt,name=groupCount" json:"groupCount,omitempty"`
	GroupIds                []*SnsGroup             `protobuf:"bytes,10,rep,name=groupIds" json:"groupIds,omitempty"`
	ObjectSource            *uint32                 `protobuf:"varint,11,opt,name=objectSource" json:"objectSource,omitempty"`
	ReferId                 *uint64                 `protobuf:"varint,12,opt,name=referId" json:"referId,omitempty"`
	BlackListCount          *uint32                 `protobuf:"varint,13,opt,name=blackListCount" json:"blackListCount,omitempty"`
	BlackList               []*SKBuiltinStringT     `protobuf:"bytes,14,rep,name=blackList" json:"blackList,omitempty"`
	TwitterInfo             *TwitterInfo            `protobuf:"bytes,15,opt,name=twitterInfo" json:"twitterInfo,omitempty"`
	GroupUserCount          *uint32                 `protobuf:"varint,16,opt,name=groupUserCount" json:"groupUserCount,omitempty"`
	GroupUser               []*SKBuiltinStringT     `protobuf:"bytes,17,rep,name=groupUser" json:"groupUser,omitempty"`
	CtocUploadInfo          *SnsPostCtocUploadInfo  `protobuf:"bytes,18,opt,name=ctocUploadInfo" json:"ctocUploadInfo,omitempty"`
	SnsPostOpearationFields *SnsPostOperationFields `protobuf:"bytes,19,opt,name=snsPostOpearationFields" json:"snsPostOpearationFields,omitempty"`
	SnsRedEnvelops          *SnsRedEnvelops         `protobuf:"bytes,20,opt,name=snsRedEnvelops" json:"snsRedEnvelops,omitempty"`
	PoiInfo                 *SKBuiltinBufferT       `protobuf:"bytes,21,opt,name=poiInfo" json:"poiInfo,omitempty"`
	FromScene               *string                 `protobuf:"bytes,22,opt,name=fromScene" json:"fromScene,omitempty"`
	CanvasInfo              *CanvasInfo             `protobuf:"bytes,23,opt,name=canvasInfo" json:"canvasInfo,omitempty"`
	MediaInfoCount          *uint32                 `protobuf:"varint,24,opt,name=mediaInfoCount" json:"mediaInfoCount,omitempty"`
	MediaInfo               []*MediaInfo            `protobuf:"bytes,25,rep,name=mediaInfo" json:"mediaInfo,omitempty"`
	WeAppInfo               *SnsWeAppInfo           `protobuf:"bytes,26,opt,name=weAppInfo" json:"weAppInfo,omitempty"`
	ClientCheckData         *SKBuiltinBufferT       `protobuf:"bytes,27,opt,name=clientCheckData" json:"clientCheckData,omitempty"`
	ExtSpamIinfo            *SKBuiltinBufferT       `protobuf:"bytes,28,opt,name=extSpamIinfo" json:"extSpamIinfo,omitempty"`
}

func (x *SnsPostRequest) Reset() {
	*x = SnsPostRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsPost_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsPostRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsPostRequest) ProtoMessage() {}

func (x *SnsPostRequest) ProtoReflect() protoreflect.Message {
	mi := &file_SnsPost_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsPostRequest.ProtoReflect.Descriptor instead.
func (*SnsPostRequest) Descriptor() ([]byte, []int) {
	return file_SnsPost_proto_rawDescGZIP(), []int{0}
}

func (x *SnsPostRequest) GetBaseRequest() *BaseRequest {
	if x != nil {
		return x.BaseRequest
	}
	return nil
}

func (x *SnsPostRequest) GetObjectDesc() *SKBuiltinBufferT {
	if x != nil {
		return x.ObjectDesc
	}
	return nil
}

func (x *SnsPostRequest) GetWithUserListCount() uint32 {
	if x != nil && x.WithUserListCount != nil {
		return *x.WithUserListCount
	}
	return 0
}

func (x *SnsPostRequest) GetWithUserList() []*SKBuiltinStringT {
	if x != nil {
		return x.WithUserList
	}
	return nil
}

func (x *SnsPostRequest) GetPrivacy() uint32 {
	if x != nil && x.Privacy != nil {
		return *x.Privacy
	}
	return 0
}

func (x *SnsPostRequest) GetSyncFlag() uint32 {
	if x != nil && x.SyncFlag != nil {
		return *x.SyncFlag
	}
	return 0
}

func (x *SnsPostRequest) GetClientId() string {
	if x != nil && x.ClientId != nil {
		return *x.ClientId
	}
	return ""
}

func (x *SnsPostRequest) GetPostBgImgType() uint32 {
	if x != nil && x.PostBgImgType != nil {
		return *x.PostBgImgType
	}
	return 0
}

func (x *SnsPostRequest) GetGroupCount() uint32 {
	if x != nil && x.GroupCount != nil {
		return *x.GroupCount
	}
	return 0
}

func (x *SnsPostRequest) GetGroupIds() []*SnsGroup {
	if x != nil {
		return x.GroupIds
	}
	return nil
}

func (x *SnsPostRequest) GetObjectSource() uint32 {
	if x != nil && x.ObjectSource != nil {
		return *x.ObjectSource
	}
	return 0
}

func (x *SnsPostRequest) GetReferId() uint64 {
	if x != nil && x.ReferId != nil {
		return *x.ReferId
	}
	return 0
}

func (x *SnsPostRequest) GetBlackListCount() uint32 {
	if x != nil && x.BlackListCount != nil {
		return *x.BlackListCount
	}
	return 0
}

func (x *SnsPostRequest) GetBlackList() []*SKBuiltinStringT {
	if x != nil {
		return x.BlackList
	}
	return nil
}

func (x *SnsPostRequest) GetTwitterInfo() *TwitterInfo {
	if x != nil {
		return x.TwitterInfo
	}
	return nil
}

func (x *SnsPostRequest) GetGroupUserCount() uint32 {
	if x != nil && x.GroupUserCount != nil {
		return *x.GroupUserCount
	}
	return 0
}

func (x *SnsPostRequest) GetGroupUser() []*SKBuiltinStringT {
	if x != nil {
		return x.GroupUser
	}
	return nil
}

func (x *SnsPostRequest) GetCtocUploadInfo() *SnsPostCtocUploadInfo {
	if x != nil {
		return x.CtocUploadInfo
	}
	return nil
}

func (x *SnsPostRequest) GetSnsPostOpearationFields() *SnsPostOperationFields {
	if x != nil {
		return x.SnsPostOpearationFields
	}
	return nil
}

func (x *SnsPostRequest) GetSnsRedEnvelops() *SnsRedEnvelops {
	if x != nil {
		return x.SnsRedEnvelops
	}
	return nil
}

func (x *SnsPostRequest) GetPoiInfo() *SKBuiltinBufferT {
	if x != nil {
		return x.PoiInfo
	}
	return nil
}

func (x *SnsPostRequest) GetFromScene() string {
	if x != nil && x.FromScene != nil {
		return *x.FromScene
	}
	return ""
}

func (x *SnsPostRequest) GetCanvasInfo() *CanvasInfo {
	if x != nil {
		return x.CanvasInfo
	}
	return nil
}

func (x *SnsPostRequest) GetMediaInfoCount() uint32 {
	if x != nil && x.MediaInfoCount != nil {
		return *x.MediaInfoCount
	}
	return 0
}

func (x *SnsPostRequest) GetMediaInfo() []*MediaInfo {
	if x != nil {
		return x.MediaInfo
	}
	return nil
}

func (x *SnsPostRequest) GetWeAppInfo() *SnsWeAppInfo {
	if x != nil {
		return x.WeAppInfo
	}
	return nil
}

func (x *SnsPostRequest) GetClientCheckData() *SKBuiltinBufferT {
	if x != nil {
		return x.ClientCheckData
	}
	return nil
}

func (x *SnsPostRequest) GetExtSpamIinfo() *SKBuiltinBufferT {
	if x != nil {
		return x.ExtSpamIinfo
	}
	return nil
}

type SnsPostResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BaseResponse *BaseResponse `protobuf:"bytes,1,req,name=baseResponse" json:"baseResponse,omitempty"`
	SnsObject    *SnsObject    `protobuf:"bytes,2,req,name=snsObject" json:"snsObject,omitempty"`
	SpamTips     *string       `protobuf:"bytes,3,opt,name=spamTips" json:"spamTips,omitempty"`
}

func (x *SnsPostResponse) Reset() {
	*x = SnsPostResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SnsPost_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnsPostResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnsPostResponse) ProtoMessage() {}

func (x *SnsPostResponse) ProtoReflect() protoreflect.Message {
	mi := &file_SnsPost_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnsPostResponse.ProtoReflect.Descriptor instead.
func (*SnsPostResponse) Descriptor() ([]byte, []int) {
	return file_SnsPost_proto_rawDescGZIP(), []int{1}
}

func (x *SnsPostResponse) GetBaseResponse() *BaseResponse {
	if x != nil {
		return x.BaseResponse
	}
	return nil
}

func (x *SnsPostResponse) GetSnsObject() *SnsObject {
	if x != nil {
		return x.SnsObject
	}
	return nil
}

func (x *SnsPostResponse) GetSpamTips() string {
	if x != nil && x.SpamTips != nil {
		return *x.SpamTips
	}
	return ""
}

var File_SnsPost_proto protoreflect.FileDescriptor

var file_SnsPost_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x53, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x4d, 0x73, 0x67, 0x42, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x53, 0x6e, 0x73, 0x42, 0x61, 0x73,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf5, 0x09, 0x0a, 0x0e, 0x53, 0x6e, 0x73, 0x50,
	0x6f, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x62, 0x61,
	0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32,
	0x0c, 0x2e, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x52, 0x0b, 0x62,
	0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x0a, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x44, 0x65, 0x73, 0x63, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x12,
	0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72,
	0x5f, 0x74, 0x52, 0x0a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x44, 0x65, 0x73, 0x63, 0x12, 0x2c,
	0x0a, 0x11, 0x77, 0x69, 0x74, 0x68, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x77, 0x69, 0x74, 0x68, 0x55,
	0x73, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x36, 0x0a, 0x0c,
	0x77, 0x69, 0x74, 0x68, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x53, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x52, 0x0c, 0x77, 0x69, 0x74, 0x68, 0x55, 0x73, 0x65, 0x72,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x63, 0x79, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x63, 0x79, 0x12, 0x1a,
	0x0a, 0x08, 0x73, 0x79, 0x6e, 0x63, 0x46, 0x6c, 0x61, 0x67, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x08, 0x73, 0x79, 0x6e, 0x63, 0x46, 0x6c, 0x61, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0d, 0x70, 0x6f, 0x73, 0x74, 0x42, 0x67,
	0x49, 0x6d, 0x67, 0x54, 0x79, 0x70, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x70,
	0x6f, 0x73, 0x74, 0x42, 0x67, 0x49, 0x6d, 0x67, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1e, 0x0a, 0x0a,
	0x67, 0x72, 0x6f, 0x75, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0a, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x25, 0x0a, 0x08,
	0x67, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x73, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09,
	0x2e, 0x53, 0x6e, 0x73, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x52, 0x08, 0x67, 0x72, 0x6f, 0x75, 0x70,
	0x49, 0x64, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x6f, 0x62, 0x6a, 0x65, 0x63,
	0x74, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x66, 0x65, 0x72,
	0x49, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x49,
	0x64, 0x12, 0x26, 0x0a, 0x0e, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x62, 0x6c, 0x61, 0x63, 0x6b,
	0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x30, 0x0a, 0x09, 0x62, 0x6c, 0x61,
	0x63, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53,
	0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x74,
	0x52, 0x09, 0x62, 0x6c, 0x61, 0x63, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x74,
	0x77, 0x69, 0x74, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0c, 0x2e, 0x54, 0x77, 0x69, 0x74, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0b,
	0x74, 0x77, 0x69, 0x74, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x26, 0x0a, 0x0e, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x55, 0x73, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x10, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0e, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x55, 0x73, 0x65, 0x72, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x12, 0x30, 0x0a, 0x09, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x55, 0x73, 0x65, 0x72,
	0x18, 0x11, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74,
	0x69, 0x6e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x52, 0x09, 0x67, 0x72, 0x6f, 0x75,
	0x70, 0x55, 0x73, 0x65, 0x72, 0x12, 0x3e, 0x0a, 0x0e, 0x63, 0x74, 0x6f, 0x63, 0x55, 0x70, 0x6c,
	0x6f, 0x61, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x12, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x53, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74, 0x43, 0x74, 0x6f, 0x63, 0x55, 0x70, 0x6c, 0x6f, 0x61,
	0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0e, 0x63, 0x74, 0x6f, 0x63, 0x55, 0x70, 0x6c, 0x6f, 0x61,
	0x64, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x51, 0x0a, 0x17, 0x73, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74,
	0x4f, 0x70, 0x65, 0x61, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73,
	0x18, 0x13, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x53, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x52,
	0x17, 0x73, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74, 0x4f, 0x70, 0x65, 0x61, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x12, 0x37, 0x0a, 0x0e, 0x73, 0x6e, 0x73, 0x52,
	0x65, 0x64, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x73, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x53, 0x6e, 0x73, 0x52, 0x65, 0x64, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70,
	0x73, 0x52, 0x0e, 0x73, 0x6e, 0x73, 0x52, 0x65, 0x64, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70,
	0x73, 0x12, 0x2c, 0x0a, 0x07, 0x70, 0x6f, 0x69, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x15, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x42, 0x75,
	0x66, 0x66, 0x65, 0x72, 0x5f, 0x74, 0x52, 0x07, 0x70, 0x6f, 0x69, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x1c, 0x0a, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x18, 0x16, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x66, 0x72, 0x6f, 0x6d, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x12, 0x2b, 0x0a,
	0x0a, 0x63, 0x61, 0x6e, 0x76, 0x61, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x17, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x0b, 0x2e, 0x43, 0x61, 0x6e, 0x76, 0x61, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a,
	0x63, 0x61, 0x6e, 0x76, 0x61, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x26, 0x0a, 0x0e, 0x6d, 0x65,
	0x64, 0x69, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x18, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0e, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x28, 0x0a, 0x09, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x18,
	0x19, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x09, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2b, 0x0a, 0x09,
	0x77, 0x65, 0x41, 0x70, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x18, 0x1a, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0d, 0x2e, 0x53, 0x6e, 0x73, 0x57, 0x65, 0x41, 0x70, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x09,
	0x77, 0x65, 0x41, 0x70, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x3c, 0x0a, 0x0f, 0x63, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x18, 0x1b, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x12, 0x2e, 0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x42, 0x75,
	0x66, 0x66, 0x65, 0x72, 0x5f, 0x74, 0x52, 0x0f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x68,
	0x65, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x12, 0x36, 0x0a, 0x0c, 0x65, 0x78, 0x74, 0x53, 0x70,
	0x61, 0x6d, 0x49, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x1c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x53, 0x4b, 0x42, 0x75, 0x69, 0x6c, 0x74, 0x69, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f,
	0x74, 0x52, 0x0c, 0x65, 0x78, 0x74, 0x53, 0x70, 0x61, 0x6d, 0x49, 0x69, 0x6e, 0x66, 0x6f, 0x22,
	0x8a, 0x01, 0x0a, 0x0f, 0x53, 0x6e, 0x73, 0x50, 0x6f, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x31, 0x0a, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x61, 0x73, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x52, 0x0c, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x28, 0x0a, 0x09, 0x73, 0x6e, 0x73, 0x4f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x02, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x53, 0x6e, 0x73, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x52, 0x09, 0x73, 0x6e, 0x73, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x12, 0x1a, 0x0a, 0x08, 0x73, 0x70, 0x61, 0x6d, 0x54, 0x69, 0x70, 0x73, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x73, 0x70, 0x61, 0x6d, 0x54, 0x69, 0x70, 0x73, 0x42, 0x0c, 0x5a, 0x0a,
	0x2e, 0x3b, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x6d, 0x73, 0x67,
}

var (
	file_SnsPost_proto_rawDescOnce sync.Once
	file_SnsPost_proto_rawDescData = file_SnsPost_proto_rawDesc
)

func file_SnsPost_proto_rawDescGZIP() []byte {
	file_SnsPost_proto_rawDescOnce.Do(func() {
		file_SnsPost_proto_rawDescData = protoimpl.X.CompressGZIP(file_SnsPost_proto_rawDescData)
	})
	return file_SnsPost_proto_rawDescData
}

var file_SnsPost_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_SnsPost_proto_goTypes = []interface{}{
	(*SnsPostRequest)(nil),         // 0: SnsPostRequest
	(*SnsPostResponse)(nil),        // 1: SnsPostResponse
	(*BaseRequest)(nil),            // 2: BaseRequest
	(*SKBuiltinBufferT)(nil),       // 3: SKBuiltinBuffer_t
	(*SKBuiltinStringT)(nil),       // 4: SKBuiltinString_t
	(*SnsGroup)(nil),               // 5: SnsGroup
	(*TwitterInfo)(nil),            // 6: TwitterInfo
	(*SnsPostCtocUploadInfo)(nil),  // 7: SnsPostCtocUploadInfo
	(*SnsPostOperationFields)(nil), // 8: SnsPostOperationFields
	(*SnsRedEnvelops)(nil),         // 9: SnsRedEnvelops
	(*CanvasInfo)(nil),             // 10: CanvasInfo
	(*MediaInfo)(nil),              // 11: MediaInfo
	(*SnsWeAppInfo)(nil),           // 12: SnsWeAppInfo
	(*BaseResponse)(nil),           // 13: BaseResponse
	(*SnsObject)(nil),              // 14: SnsObject
}
var file_SnsPost_proto_depIdxs = []int32{
	2,  // 0: SnsPostRequest.baseRequest:type_name -> BaseRequest
	3,  // 1: SnsPostRequest.objectDesc:type_name -> SKBuiltinBuffer_t
	4,  // 2: SnsPostRequest.withUserList:type_name -> SKBuiltinString_t
	5,  // 3: SnsPostRequest.groupIds:type_name -> SnsGroup
	4,  // 4: SnsPostRequest.blackList:type_name -> SKBuiltinString_t
	6,  // 5: SnsPostRequest.twitterInfo:type_name -> TwitterInfo
	4,  // 6: SnsPostRequest.groupUser:type_name -> SKBuiltinString_t
	7,  // 7: SnsPostRequest.ctocUploadInfo:type_name -> SnsPostCtocUploadInfo
	8,  // 8: SnsPostRequest.snsPostOpearationFields:type_name -> SnsPostOperationFields
	9,  // 9: SnsPostRequest.snsRedEnvelops:type_name -> SnsRedEnvelops
	3,  // 10: SnsPostRequest.poiInfo:type_name -> SKBuiltinBuffer_t
	10, // 11: SnsPostRequest.canvasInfo:type_name -> CanvasInfo
	11, // 12: SnsPostRequest.mediaInfo:type_name -> MediaInfo
	12, // 13: SnsPostRequest.weAppInfo:type_name -> SnsWeAppInfo
	3,  // 14: SnsPostRequest.clientCheckData:type_name -> SKBuiltinBuffer_t
	3,  // 15: SnsPostRequest.extSpamIinfo:type_name -> SKBuiltinBuffer_t
	13, // 16: SnsPostResponse.baseResponse:type_name -> BaseResponse
	14, // 17: SnsPostResponse.snsObject:type_name -> SnsObject
	18, // [18:18] is the sub-list for method output_type
	18, // [18:18] is the sub-list for method input_type
	18, // [18:18] is the sub-list for extension type_name
	18, // [18:18] is the sub-list for extension extendee
	0,  // [0:18] is the sub-list for field type_name
}

func init() { file_SnsPost_proto_init() }
func file_SnsPost_proto_init() {
	if File_SnsPost_proto != nil {
		return
	}
	file_MicroMsgBase_proto_init()
	file_MicroSnsBase_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SnsPost_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsPostRequest); i {
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
		file_SnsPost_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnsPostResponse); i {
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
			RawDescriptor: file_SnsPost_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SnsPost_proto_goTypes,
		DependencyIndexes: file_SnsPost_proto_depIdxs,
		MessageInfos:      file_SnsPost_proto_msgTypes,
	}.Build()
	File_SnsPost_proto = out.File
	file_SnsPost_proto_rawDesc = nil
	file_SnsPost_proto_goTypes = nil
	file_SnsPost_proto_depIdxs = nil
}
