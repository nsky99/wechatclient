package scene

import (
	"time"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneHeartBeat struct {
	UserInfo *wechatsdk.WxUserInfo
}

func (ns *NetSceneHeartBeat) Req2Buf() ([]byte, error) {

	time := uint32(time.Now().Unix())
	heartBeat := &micromsg.HeartBeatRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(uint32(config.WechatClientVersion)),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},
		TimeStamp: proto.Uint32(time),
	}

	heartBeatReqData, _ := proto.Marshal(heartBeat)

	nsb := NetSeceneBase{
		UserInfo:  ns.UserInfo,
		CmdId:     CmdIdHeartBeat,
		ReportArg: ReportArgHeartBeat,
	}

	return nsb.EncodeCommonReqBuf(heartBeatReqData), nil
}

func (ns *NetSceneHeartBeat) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	Rsp := &micromsg.HeartBeatResponse{}
	proto.Unmarshal(rspByte, Rsp)

	return Rsp, nil
}
