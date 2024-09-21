package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

type NetSceneGetContact struct {
	UserInfo  *wechatsdk.WxUserInfo
	UserNames []string // 联系人id
}

func (ns *NetSceneGetContact) Req2Buf() ([]byte, error) {
	request := &micromsg.GetContactRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(0),
		},
	}
	request.UserCount = proto.Uint32(uint32(len(ns.UserNames)))

	for _, username := range ns.UserNames {
		userName := &micromsg.SKBuiltinStringT{
			String_: proto.String(username),
		}
		request.UserNameList = append(request.UserNameList, userName)
	}

	request_data, _ := proto.Marshal(request)

	nsb := NetSeceneBase{
		CmdId:     CmdIdGetContact,
		ReportArg: ReportArgGetContact,
		UserInfo:  ns.UserInfo,
	}

	return nsb.EncodeCommonReqBuf(request_data), nil
}

func (ns *NetSceneGetContact) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	response_data := nsb.DecodeCommonRspBuf(payload)
	response := &micromsg.GetContactResponse{}
	proto.Unmarshal(response_data, response)

	return response, nil
}
