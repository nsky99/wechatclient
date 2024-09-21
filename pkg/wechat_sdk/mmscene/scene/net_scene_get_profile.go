package scene

import (
	"fmt"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneGetProfile struct {
	UserInfo *wechatsdk.WxUserInfo
}

// 将请求对象序列化为字节流，以便发送到服务器
func (ns *NetSceneGetProfile) Req2Buf() ([]byte, error) {
	GetProfileRequest := &micromsg.GetProfileRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},
		UserName: proto.String(ns.UserInfo.UserName),
	}

	GetProfileRequestData, err := proto.Marshal(GetProfileRequest)
	if err != nil {
		fmt.Println(err)
	}

	nsb := NetSeceneBase{
		CmdId:     CmdIdGetProfile,
		ReportArg: ReportArgGetProfile,
		UserInfo:  ns.UserInfo,
	}

	return nsb.EncodeCommonReqBuf(GetProfileRequestData), nil
}

// 将从服务器接收到的字节流反序列化为响应对象
func (ns *NetSceneGetProfile) Buf2Rsp(data []byte) (interface{}, error) {
	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(data)

	ProfileRsp := &micromsg.GetProfileResponse{}
	err := proto.Unmarshal(rspByte, ProfileRsp)
	if err != nil {
		return nil, err
	}
	return ProfileRsp, err
}
