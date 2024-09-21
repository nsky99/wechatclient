package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneLogOut struct {
	UserInfo *wechatsdk.WxUserInfo
}

func (ns *NetSceneLogOut) Req2Buf() ([]byte, error) {
	logoutReq := &micromsg.LogOutRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},
		Scene: proto.Uint32(0),
	}

	logoutReqData, _ := proto.Marshal(logoutReq)

	nsb := NetSeceneBase{
		CmdId:     CmdIdLogout,
		ReportArg: ReportArgLogout,
		UserInfo:  ns.UserInfo,
	}

	return nsb.EncodeCommonReqBuf(logoutReqData), nil
}

func (ns *NetSceneLogOut) Buf2Rsp(payload []byte) (interface{}, error) {
	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	logoutRsp := &micromsg.LogOutResponse{}
	proto.Unmarshal(rspByte, logoutRsp)

	return logoutRsp, nil
}
