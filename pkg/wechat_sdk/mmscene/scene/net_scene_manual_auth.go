package scene

import (
	"crypto/elliptic"
	"fmt"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"

	"google.golang.org/protobuf/proto"
)

type NetSceneManualAuth struct {
	UserInfo      *wechatsdk.WxUserInfo
	WxLoginPubKey []byte
	WxLoginPriKey []byte
}

func (ns *NetSceneManualAuth) Req2Buf() ([]byte, error) {
	// 生成loginkey
	privateKey, publicKey := packet.GenEcdhKeyPair(elliptic.P224())
	if len(privateKey) == 0 || len(publicKey) == 0 {
		return nil, fmt.Errorf("生成登录密钥对失败")
	}
	ns.WxLoginPubKey = publicKey
	ns.WxLoginPriKey = privateKey

	aeskey := []byte(packet.Random(16)) //获取随机密钥
	if len(aeskey) == 0 {
		return nil, fmt.Errorf("生成随机密钥失败")
	}

	accountRequest := &micromsg.ManualAuthRsaReqData{
		RandomEncryKey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(len(aeskey))),
			Buffer: aeskey,
		},
		CliPubECDHKey: &micromsg.ECDHKey{
			Nid: proto.Int32(713), //713
			Key: &micromsg.SKBuiltinBufferT{
				ILen:   proto.Int32(int32(len(publicKey))),
				Buffer: publicKey[:],
			},
		},
		Username: proto.String(ns.UserInfo.UserName),
		Pwd:      proto.String(ns.UserInfo.Password),
	}

	softType := string("<softtype><k1>12th Gen Intel(R) Core(TM) i5-1240P</k1><k2>fffbcbbf</k2><k3>Dell Inc. 0RWT8G A00</k3><k4>unknown</k4><k5>475GB</k5><k14>ac91a12c4c0850284a2fb9570a002700000a00155d40612d00155da8c9c950284a2fb95350284a2fb95452284a2fb953</k14><k43>{EC957FDF-D75C-484E-B0E7-0A0FF8514225}</k43><k66>Intel(R) UHD Graphics</k66><k67>1024MB</k67><k68>16GB</k68><k69>PC SN740 NVMe WD 512GB 512GB [install] [data]</k69></softtype>")
	Signature := string("ProcessId:36876;ProcessName:C:\\Program Files (x86)\\Tencent\\WeChat\\WeChat.exe;ClassName:Qt5QWindowIcon;qbMachineId:;MachineId:ac91a12c4c0850284a2fb9570a002700000a00155d40612d00155da8c9c950284a2fb95350284a2fb95452284a2fb953 + -1077150721;QBVerSion:3.9.9.43\n")
	deviceRequest := &micromsg.ManualAuthAesReqData{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.UserInfo.DeviceID),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.UserInfo.DeviceType),
			Scene:         proto.Uint32(1),
		},
		BaseReqInfo:    &micromsg.BaseAuthReqInfo{},
		SoftType:       proto.String(softType),
		BuiltinIPSeq:   proto.Uint32(0),
		Signature:      proto.String(Signature),
		DeviceName:     proto.String(ns.UserInfo.DeviceName),
		DeviceType:     proto.String(ns.UserInfo.DeviceType),
		Language:       proto.String("zh_CN"), // 语言
		Timezone:       proto.String("8"),     // 时区
		Channel:        proto.Int32(500),      //
		DeviceBrand:    proto.String(ns.UserInfo.DeviceType),
		DeviceModel:    proto.String(ns.UserInfo.DeviceType),
		OsType:         proto.String(ns.UserInfo.DeviceType),
		BundleID:       proto.String("0"),
		InputType:      proto.Uint32(2),
		ClientCheckDat: &micromsg.SKBuiltinBufferT{},
	}

	requset := &micromsg.ManualAuthRequest{
		RsaReqData: accountRequest,
		AesReqData: deviceRequest,
	}
	reqdata, _ := proto.Marshal(requset)
	nsb := NetSeceneBase{
		CmdId:     CmdIdSecManualAuth, // 长连接才会使用到
		ReportArg: ReportArgSecManualAuth,
		UserInfo:  ns.UserInfo,
	}
	return nsb.EncodeEcdhReqBuf(reqdata), nil
}

func (ns *NetSceneManualAuth) Buf2Rsp(data []byte) (interface{}, error) {
	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeEcdhRspBuf(data)
	UnifyAuthRsp := &micromsg.UnifyAuthResponse{}
	err := proto.Unmarshal(rspByte, UnifyAuthRsp)
	if err != nil {
		return nil, err
	}
	return UnifyAuthRsp, err
}
