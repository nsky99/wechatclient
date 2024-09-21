package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"
)

// 网络场景基础接口
type INetSceneBase interface {
	// 将请求对象序列化为字节流，以便发送到服务器
	Req2Buf() ([]byte, error)

	// 将从服务器接收到的字节流反序列化为响应对象
	Buf2Rsp(data []byte) (interface{}, error)
}

// 网络场景基础数据
type NetSeceneBase struct {
	CmdId     uint32
	ReportArg uint32
	UserInfo  *wechatsdk.WxUserInfo
}

func (ns *NetSeceneBase) EncodeEcdhReqBuf(data []byte) []byte {
	// 加密
	mmpkt := packet.MmPacket{
		EcdhClient: ns.UserInfo.EcdhClient,
	}
	EncodeData := mmpkt.EncodeEcdhEncryptPack(data)

	// 组包
	mmpkt = packet.MmPacket{
		ClientVersion: uint32(config.WechatClientVersion), // 客户端版本
		Uin:           ns.UserInfo.AuthUin,                // 唯一标识符
		ReportArg:     ns.ReportArg,                       // 功能id
		Sn:            10010,                              // 地区序列号
		Cookies:       ns.UserInfo.Cookies,                // cookies
		Calgo:         0x2,                                // 不压缩
		Ealgo:         0xC,                                // 加密算法
		HaveCheckSum:  true,                               // 是否需要校验和
		Clen:          len(EncodeData),                    // 数据压缩前的长度
		Cdlen:         len(EncodeData),                    // 数据压缩后的长度
	}
	return mmpkt.PackMessage(EncodeData)
}

func (ns *NetSeceneBase) DecodeEcdhRspBuf(data []byte) []byte {
	// 解包
	mmPkt := packet.MmPacket{
		ServerSessionKey:      []byte{},
		SessionKeyOrNotifyKey: []byte{},
		EcdhClient:            ns.UserInfo.EcdhClient,
	}

	body := mmPkt.DecodePack(data)

	// 保存cookies
	ns.UserInfo.Cookies = mmPkt.Cookies

	return body
}

func (ns *NetSeceneBase) EncodeCommonReqBuf(data []byte) []byte {

	mmpkt := packet.MmPacket{
		ClientVersion: uint32(config.WechatClientVersion), // 客户端版本
		Uin:           ns.UserInfo.AuthUin,                // 唯一标识符
		ReportArg:     ns.ReportArg,                       // 功能id
		Sn:            10010,                              //
		Cookies:       ns.UserInfo.Cookies,                // cookies
		Ealgo:         5,                                  // 加密算法
		SessionKey:    ns.UserInfo.AuthDecodeSessionKey,   // 加密秘钥
		Loginecdhkey:  ns.UserInfo.AuthLoginEcdhKey,
		HaveCheckSum:  true,
	}

	return mmpkt.EncodePack(data)
}

func (ns *NetSeceneBase) DecodeCommonRspBuf(data []byte) []byte {
	// 解包
	mmPkt := packet.MmPacket{
		ServerSessionKey:      []byte{},
		SessionKeyOrNotifyKey: ns.UserInfo.AuthDecodeSessionKey,
	}

	body := mmPkt.DecodePack(data)

	// 保存cookies
	ns.UserInfo.Cookies = mmPkt.Cookies

	return body
}
