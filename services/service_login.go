package services

import (
	"fmt"
	"wechatclient/manager/wx_client_mgr"
	"wechatclient/manager/wx_client_mgr/wx_client"
)

func GetLoginQRCode(sessionId, deviceID, deviceType, deviceName string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	var wxClient *wx_client.WxClient
	wxClient = wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		wxClient = wx_client.NewWxClient(deviceID, deviceType, deviceName)
		wx_client_mgr.WxClientMgr.Add(sessionId, wxClient)
	}

	response, err := wxClient.GetLoginQrCode(deviceID, deviceType, deviceName)
	if err != nil {
		return "", err
	}
	return response, nil
}

func CheckLoginQRCode(sessionId string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.CheckLoginQrCode()
	if err != nil {
		return "", err
	}
	return response, nil
}

func SecManualAuth(sessionId string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.SecManualAuth()
	if err != nil {
		return "", err
	}
	return response, nil
}

func LogOut(sessionId string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.LogOut()
	if err != nil {
		return "", err
	}
	return response, nil
}

func GetProFile(sessionId string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.GetProFile()
	if err != nil {
		return "", err
	}
	return response, nil
}
