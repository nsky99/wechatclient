package wechatsdk

import (
	"fmt"
	"wechatclient/pkg/wechat_sdk/config"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"
	wx_services "wechatclient/pkg/wechat_sdk/services"
)

// 保持每个微信用户的连接信息和微信登录信息
type WxUserInfo struct {
	// 设备信息
	DeviceID   string // 账号登录的设备id
	DeviceType string // 账号登录的设备类型
	DeviceName string // 账号登录的设备名称

	// 登录二维码信息
	QrcodeUuid      string // 登录二维码uuid
	QrScanUrl       string // 登录二维码链接
	QrcodeNotifyKey []byte // 用来校验是否登录的key

	// 授权信息
	EcdhClient           *packet.HybridEcdhClient // 非auth接口使用
	Cookies              []byte                   // 接口cookie
	AuthUin              uint32
	AuthSvrPublicEcdhKey []byte
	AuthLoginEcdhKey     []byte // AuthSvrPublicEcdhKey + ClientPrivateEcdhKey
	AuthSessionKey       []byte
	AuthDecodeSessionKey []byte // 解密后的SessionKey
	AuthAutoKey          []byte
	CliDBEncryptKey      []byte
	NewClientVersion     uint32 // 新客户端版本
	UpdateFlag           uint32 // 是否需要更新客户端
	AuthResultFlag       uint32 // 认证结果

	// 用户信息
	UserName   string // 用户名wxid
	NickName   string // 用户昵称
	Password   string // 伪密码
	BindUin    uint32 // 绑定的qq
	BindEmail  string // 绑定的邮箱
	BindMobile string // 绑定的手机号
	Alias      string // 别名
	SafeDevice uint32 // 是否是安全设备

	// 同步消息的一些信息
	SyncKey []byte // newinit获取

	// 网络连接
	Services *wx_services.WxServices
}

func NewWxUserInfo(DeviceId, DeviceType, DeviceName string) *WxUserInfo {
	info := &WxUserInfo{
		DeviceID:   DeviceId,
		DeviceType: DeviceType,
		DeviceName: DeviceName,
		EcdhClient: &packet.HybridEcdhClient{
			HybridEcdhInitServerPubKey: packet.HybridEcdhInitServerPubKey,
			HybridEcdsaVerifyPubKey:    packet.HybridEcdsaVerifyPubKey,
		},
	}

	s, err := wx_services.NewCreateWxServices(
		config.WxLongHostList[1],
		config.WxPortList[2],
		config.WxShortHostList[1],
		config.WxPortList[1],
	)
	if err != nil {
		fmt.Println("create wx services:", err)
		return nil
	}
	info.Services = s
	return info
}

func (info *WxUserInfo) GetServices() *wx_services.WxServices {
	return info.Services
}
