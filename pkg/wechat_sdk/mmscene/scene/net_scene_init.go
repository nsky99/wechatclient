package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneInit struct {
	UserInfo *wechatsdk.WxUserInfo
}

func (ns *NetSceneInit) Req2Buf() ([]byte, error) {

	req := &micromsg.NewInitRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(uint32(config.WechatClientVersion)),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},
		CurrentSynckey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(0)),
			Buffer: nil,
		},
		MaxSynckey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(0)),
			Buffer: nil,
		},
		Username: proto.String(ns.UserInfo.UserName),
	}

	reqdata, _ := proto.Marshal(req)

	nsb := NetSeceneBase{
		UserInfo:  ns.UserInfo,
		CmdId:     CmdIdInit,
		ReportArg: ReportArgNewInit,
	}

	return nsb.EncodeCommonReqBuf(reqdata), nil
}

func (ns *NetSceneInit) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	rsp := &micromsg.NewInitResponse{}
	proto.Unmarshal(rspByte, rsp)

	return rsp, nil
}
