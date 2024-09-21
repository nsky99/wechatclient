package services

import (
	"errors"
	"fmt"
	"strings"
	"wechatclient/manager/wx_client_mgr"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
)

func InitContact(sessionId string, CurWxContactSeq, CurWxChatRoomSeq int32) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.InitContact(CurWxContactSeq, CurWxChatRoomSeq)
	if err != nil {
		return "", err
	}
	return response, nil
}

func InitContactList(sessionId string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	var (
		CurWxContactSeq  = int32(0)
		CurWxChatRoomSeq = int32(0)
		responseList     []*micromsg.InitContactResponse
		ghList           []string
		roomList         []string
		personList       []string
	)

	for {
		response, err := wxClient.InitContact(CurWxContactSeq, CurWxChatRoomSeq)
		if err != nil {
			return "", err
		}
		initCtxRsp := response.(*micromsg.InitContactResponse)
		if initCtxRsp.GetBaseResponse().GetRet() != 0 {
			return "", errors.New("请求错误")
		}

		responseList = append(responseList, initCtxRsp)
		CurWxContactSeq = initCtxRsp.GetCurrentWxcontactSeq()
		CurWxChatRoomSeq = initCtxRsp.GetCurrentChatRoomContactSeq()
		for _, username := range initCtxRsp.GetContactUsernameList() {
			if strings.HasPrefix(username, "gh_") {
				ghList = append(ghList, username)
				continue
			} else if strings.HasSuffix(username, "@chatroom") {
				roomList = append(roomList, username)
				continue
			} else {
				personList = append(personList, username)
			}
		}

		// 结束标志
		if initCtxRsp.GetCountinueFlag() == 0 {
			break
		}
	}
	fmt.Println("公众号列表:", ghList)
	fmt.Println("群聊列表:", roomList)
	fmt.Println("联系人列表:", personList)
	return responseList, nil
}

func GetContact(sessionId string, ContactWxid []string) (interface{}, error) {
	// 走mgr 来查询账户然后走mgr去调用功能
	wxClient := wx_client_mgr.WxClientMgr.Get(sessionId)
	// 缓存中没有找到账号, 账号未登录
	if wxClient == nil {
		fmt.Printf("没有找到 %s 会话绑定的账号\n", sessionId)
		return nil, fmt.Errorf("没有找到 %s 会话绑定的账号", sessionId)
	}

	response, err := wxClient.GetContact(ContactWxid)
	if err != nil {
		return "", err
	}
	return response, nil
}
