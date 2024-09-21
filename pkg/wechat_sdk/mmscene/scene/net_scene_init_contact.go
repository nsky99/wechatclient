package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneInitContact struct {
	UserInfo                  *wechatsdk.WxUserInfo
	CurrentWxcontactSeq       int32
	CurrentChatRoomContactSeq int32
}

func (ns *NetSceneInitContact) Req2Buf() ([]byte, error) {

	req := &micromsg.InitContactRequest{
		Username:                  proto.String(ns.UserInfo.UserName),
		CurrentWxcontactSeq:       proto.Int32(ns.CurrentWxcontactSeq),
		CurrentChatRoomContactSeq: proto.Int32(ns.CurrentChatRoomContactSeq),
	}

	reqdata, _ := proto.Marshal(req)

	nsb := NetSeceneBase{
		CmdId:     CmdInvalid,
		ReportArg: ReportArgInitContact,
		UserInfo:  ns.UserInfo,
	}

	return nsb.EncodeCommonReqBuf(reqdata), nil
}

func (ns *NetSceneInitContact) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rsp := &micromsg.InitContactResponse{}

	if len(payload) != 0 {
		rspByte := nsb.DecodeCommonRspBuf(payload)
		proto.Unmarshal(rspByte, rsp)
	}

	return rsp, nil
}
