package scene

import (
	"fmt"
	"time"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"

	"google.golang.org/protobuf/proto"
)

type NetSceneCheckLoginQrcode struct {
	UserInfo   *wechatsdk.WxUserInfo
	DeviceId   string
	DeviceType string
	DeviceName string
	Uuid       string
	NotifyKey  []byte
}

func (ns *NetSceneCheckLoginQrcode) Req2Buf() ([]byte, error) {

	randomKey := []byte(packet.Random(0x10)) // 获取随机密钥

	CheckLoginQrCodeProto := &micromsg.CheckLoginQRCodeRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    randomKey,
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.DeviceId),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.DeviceType),
			Scene:         proto.Uint32(0),
		},
		RandomEncryKey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(len(randomKey))),
			Buffer: randomKey,
		},
		Uuid:      &ns.Uuid,
		Opcode:    proto.Uint32(0),
		Timestamp: proto.Uint32(uint32(time.Now().Unix())),
	}
	CheckLoginQrCodeProtoData, _ := proto.Marshal(CheckLoginQrCodeProto)

	nsb := NetSeceneBase{
		CmdId:     CmdIdCheckLoginQrCode,
		ReportArg: ReportArgCheckLoginQrCode,
		UserInfo:  ns.UserInfo,
	}
	return nsb.EncodeEcdhReqBuf(CheckLoginQrCodeProtoData), nil
}

func (ns *NetSceneCheckLoginQrcode) Buf2Rsp(payload []byte) (interface{}, error) {
	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeEcdhRspBuf(payload)

	checkLoginQrcodeRsp := &micromsg.CheckLoginQRCodeResponse{}
	err := proto.Unmarshal(rspByte, checkLoginQrcodeRsp)
	if err != nil {
		return nil, err
	}

	// 二维码过期了
	if checkLoginQrcodeRsp.BaseResponse.GetRet() != 0 {
		return nil, fmt.Errorf("qrcode time out")
	}

	// 解密二维码返回信息
	loginQRCodeNotifyByte := packet.AesDecrypt(checkLoginQrcodeRsp.NotifyPkg.NotifyData.GetBuffer(), ns.NotifyKey)
	loginQRCodeNotify := &micromsg.LoginQRCodeNotify{}
	err = proto.Unmarshal(loginQRCodeNotifyByte, loginQRCodeNotify)
	if err != nil {
		return nil, err
	}
	return loginQRCodeNotify, nil
}
