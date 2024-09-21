package wx_client_mgr

import (
	"wechatclient/manager/wx_client_mgr/wx_client"

	"github.com/gogf/gf/container/gmap"
)

type WxClientManager struct {
	wxClientMap *gmap.Map
}

var (
	WxClientMgr = NewWxClientManager()
)

// 创建一个wx账号管理器，用来管理所有的crm账号账号下的微信账号
func NewWxClientManager() *WxClientManager {
	return &WxClientManager{
		wxClientMap: gmap.New(true),
	}
}

// 添加微信账号
func (mgr *WxClientManager) Add(uuid string, wxAccount *wx_client.WxClient) {
	// 添加一个crm 账号到crm 管理器中
	mgr.wxClientMap.Set(uuid, wxAccount)
}

// 根据uuid获取微信账号
func (mgr *WxClientManager) Get(uuid string) *wx_client.WxClient {
	wxClient := mgr.wxClientMap.Get(uuid)
	if wxClient == nil {
		return nil
	}
	return wxClient.(*wx_client.WxClient)
}

// 根据uuid删除微信账号
func (mgr *WxClientManager) Del(uuid string) {
	mgr.wxClientMap.Remove(uuid)
}
