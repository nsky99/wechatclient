package wx_services

import "wechatclient/pkg/wechat_sdk/mmtls"

type WxServices struct {
	// 网络连接
	LinkLong  *mmtls.MmtlsLinkLong
	LinkShort *mmtls.MmtlsLinkShort
}

func NewCreateWxServices(long_host, long_port, short_host, short_port string) (*WxServices, error) {
	wxs := &WxServices{
		LinkLong:  mmtls.NewMmtlsLinkLong(long_host, long_port),
		LinkShort: mmtls.NewMmtlsLinkShort(short_host, short_port),
	}

	// 长链接握手
	if err := wxs.LinkLong.Handshake(); err != nil {
		return nil, err
	}

	// 长连接检测是否成功连接
	if err := wxs.LinkLong.SendNoop(); err != nil {
		return nil, err
	}

	if err := wxs.LinkLong.RecvNoop(); err != nil {
		return nil, err
	}

	// 短链接握手
	if err := wxs.LinkShort.Handshake(); err != nil {
		return nil, err
	}

	return wxs, nil
}

// 获取短链接用于http请求
func (s *WxServices) GetShortLink() *mmtls.MmtlsLinkShort {
	return s.LinkShort
}
