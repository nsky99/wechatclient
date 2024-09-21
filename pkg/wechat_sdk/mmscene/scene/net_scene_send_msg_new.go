package scene

import (
	"time"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneSendMsgNew struct {
	UserInfo    *wechatsdk.WxUserInfo
	Toid        string // 发送给谁
	Content     string // 发送的内容
	Type        uint32 // 发送的消息类型
	ClientMsgId uint32
}

func (ns *NetSceneSendMsgNew) Req2Buf() ([]byte, error) {
	req := &micromsg.NewSendMsgRequest{
		Count: proto.Int32(1),
	}

	msg_req := &micromsg.MicroMsgRequestNew{
		ToUserName: &micromsg.SKBuiltinStringT{
			String_: proto.String(ns.Toid),
		},
		Content:     proto.String(ns.Content),
		Type:        proto.Uint32(ns.Type),
		CreateTime:  proto.Uint32(uint32(time.Now().Unix())),
		ClientMsgId: proto.Uint32(ns.ClientMsgId),
		MsgSource:   proto.String("<msgsource><sec_msg_node><alnode><fr>1</fr></alnode></sec_msg_node></msgsource>"),
	}

	req.MsgRequestList = append(req.MsgRequestList, msg_req)

	reqdata, _ := proto.Marshal(req)

	nsb := NetSeceneBase{
		UserInfo:  ns.UserInfo,
		CmdId:     CmdIdSendMsgNew,
		ReportArg: ReportArgSendMsgNew,
	}

	return nsb.EncodeCommonReqBuf(reqdata), nil
}

func (ns *NetSceneSendMsgNew) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	rsp := &micromsg.NewSendMsgResponse{}
	proto.Unmarshal(rspByte, rsp)

	return rsp, nil
}
