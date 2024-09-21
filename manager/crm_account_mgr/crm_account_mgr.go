package crm_account_mgr

import (
	"wechatclient/manager/crm_account_mgr/crm_account"

	"github.com/gogf/gf/container/gmap"
)

type CrmAccountMgr struct {
	crmAccountMgrMap *gmap.Map
}

// 创建一个crm账号管理器，用来管理所有的crm账号
func NewCrmAccountMgr() *CrmAccountMgr {
	return &CrmAccountMgr{
		crmAccountMgrMap: gmap.New(true),
	}
}

func (mgr *CrmAccountMgr) Add(uuid string, crmAccount crm_account.CrmAccount) {
	// 添加一个crm 账号到crm 管理器中
	mgr.crmAccountMgrMap.Set(uuid, crmAccount)
}
