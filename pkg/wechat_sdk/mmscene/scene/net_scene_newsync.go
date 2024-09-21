package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneNewSync struct {
	UserInfo *wechatsdk.WxUserInfo
	Scene    uint32 // 同步场景
}

func (ns *NetSceneNewSync) Req2Buf() ([]byte, error) {
	req := &micromsg.NewSyncRequest{
		Oplog: &micromsg.CmdList{},

		Selector: proto.Uint32(uint32(262151)), // 固定值

		KeyBuf: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(len(ns.UserInfo.SyncKey))),
			Buffer: ns.UserInfo.SyncKey,
		},
		Scene:         proto.Uint32(ns.Scene),
		DeviceType:    proto.String(ns.UserInfo.DeviceType),
		NetworkType:   proto.Uint32(3),
		SyncMsgDigest: proto.Uint32(1),
	}

	reqdata, _ := proto.Marshal(req)

	nsb := NetSeceneBase{
		UserInfo:  ns.UserInfo,
		CmdId:     CmdIdNewSync,
		ReportArg: ReportArgNewSync,
	}

	return nsb.EncodeCommonReqBuf(reqdata), nil
}

func (ns *NetSceneNewSync) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	rsp := &micromsg.NewSyncResponse{}
	proto.Unmarshal(rspByte, rsp)

	return rsp, nil
}
