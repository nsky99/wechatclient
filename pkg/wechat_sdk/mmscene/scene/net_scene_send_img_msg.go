package scene

import (
	"fmt"
	"time"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/pkg/wechat_sdk/util"

	"google.golang.org/protobuf/proto"
)

type NetSceneSendImgMsg struct {
	UserInfo  *wechatsdk.WxUserInfo
	Toid      string
	ImageData []byte
}

func (ns *NetSceneSendImgMsg) Req2Buf() ([]byte, error) {

	ClientImgId := fmt.Sprintf("%v_%v", util.AInfo.Wxid, time.Now().Unix())

	req := &micromsg.UploadMsgImgRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},

		ClientImgId: &micromsg.SKBuiltinStringT{
			String_: proto.String(ClientImgId),
		},
		FromUserName: &micromsg.SKBuiltinStringT{
			String_: proto.String(ns.UserInfo.UserName),
		},
		ToUserName: &micromsg.SKBuiltinStringT{
			String_: proto.String(ns.Toid),
		},
		TotalLen: proto.Uint32(uint32(len(ns.ImageData))),
		StartPos: proto.Uint32(uint32(0)),
		DataLen:  proto.Uint32(uint32(len(ns.ImageData))),
		Data: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(len(ns.ImageData))),
			Buffer: []byte(ns.ImageData),
		},
		MsgType:  proto.Uint32(3),
		EncryVer: proto.Int32(0),
		QeqTime:  proto.Uint32(uint32(time.Now().Unix())),
		// MessageExt: proto.String("png"),
	}

	reqdata, _ := proto.Marshal(req)

	nsb := NetSeceneBase{
		UserInfo:  ns.UserInfo,
		CmdId:     CmdIdUploadMsgImg,
		ReportArg: ReportArgUploadMsgImg,
	}

	return nsb.EncodeCommonReqBuf(reqdata), nil
}

func (ns *NetSceneSendImgMsg) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeCommonRspBuf(payload)
	rsp := &micromsg.UploadMsgImgResponse{}
	proto.Unmarshal(rspByte, rsp)

	return rsp, nil
}
