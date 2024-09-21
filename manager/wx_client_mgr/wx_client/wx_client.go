package wx_client

import (
	"crypto/elliptic"
	"errors"
	"os"
	wechatsdk "wechatclient/pkg/wechat_sdk"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"
	"wechatclient/pkg/wechat_sdk/mmscene/scene"
)

type WxClient struct {
	// 保存微信用户信息
	UserInfo *wechatsdk.WxUserInfo
}

func NewWxClient(DeviceId, DeviceType, DeviceName string) *WxClient {
	return &WxClient{
		UserInfo: wechatsdk.NewWxUserInfo(DeviceId, DeviceType, DeviceName),
	}
}

// 获取登录二维码
func (account *WxClient) GetLoginQrCode(deviceID, deviceType, deviceName string) (interface{}, error) {
	scene := &scene.NetSceneGetLoginQrcode{
		DeviceId:   deviceID,
		DeviceType: deviceType,
		DeviceName: deviceName,
		UserInfo:   account.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		panic("NetSceneGetLoginQrcode req2buf faild")
	}

	// 请求
	response_data, err := account.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/getloginqrcode",
		request_data,
	)
	if err != nil {
		panic("NetSceneGetLoginQrcode Request faild")
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		panic("NetSceneGetLoginQrcode Buf2Rsp faild")
	}
	account.UserInfo.QrcodeUuid = rsp.(*micromsg.GetLoginQRCodeResponse).GetUuid()
	account.UserInfo.QrcodeNotifyKey = rsp.(*micromsg.GetLoginQRCodeResponse).GetNotifyKey().GetBuffer()
	return rsp.(*micromsg.GetLoginQRCodeResponse), nil
}

// 检测登录二维码
func (account *WxClient) CheckLoginQrCode() (interface{}, error) {
	scene := &scene.NetSceneCheckLoginQrcode{
		DeviceId:   account.UserInfo.DeviceID,
		DeviceType: account.UserInfo.DeviceType,
		DeviceName: account.UserInfo.DeviceName,
		Uuid:       account.UserInfo.QrcodeUuid,
		NotifyKey:  account.UserInfo.QrcodeNotifyKey,
		UserInfo:   account.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := account.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/checkloginqrcode",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	// 保存用户登录成功信息
	if rsp.(*micromsg.LoginQRCodeNotify).GetStatus() == 2 {
		account.UserInfo.UserName = rsp.(*micromsg.LoginQRCodeNotify).GetUsername()
		account.UserInfo.Password = rsp.(*micromsg.LoginQRCodeNotify).GetPwd()
	}

	return rsp.(*micromsg.LoginQRCodeNotify), nil
}

// 检测登录二维码
func (client *WxClient) SecManualAuth() (interface{}, error) {

	// 检测参数
	if client.UserInfo.UserName == "" || client.UserInfo.Password == "" {
		return nil, errors.New("请先扫描二维码确认登录后再授权")
	}

	scene := &scene.NetSceneManualAuth{
		UserInfo: client.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/secmanualauth",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	// 保存登录成功的信息
	authRsp := rsp.(*micromsg.UnifyAuthResponse)
	if authRsp.BaseResponse.GetRet() == 0 && authRsp.GetUnifyAuthSectFlag() > 0 {
		// 保存授权信息
		client.UserInfo.AuthUin = authRsp.GetAuthSectResp().GetUin()
		client.UserInfo.AuthSvrPublicEcdhKey = authRsp.GetAuthSectResp().GetSvrPubECDHKey().GetKey().GetBuffer()
		client.UserInfo.AuthLoginEcdhKey = packet.EcdhSharedSecret(
			elliptic.P224(),
			authRsp.GetAuthSectResp().GetSvrPubECDHKey().GetKey().GetBuffer(),
			[]byte(scene.WxLoginPriKey),
			1,
		)

		client.UserInfo.AuthSessionKey = authRsp.GetAuthSectResp().GetSessionKey().GetBuffer()
		client.UserInfo.AuthDecodeSessionKey =
			packet.AesDecrypt(authRsp.GetAuthSectResp().GetSessionKey().GetBuffer(), client.UserInfo.AuthLoginEcdhKey[:0x10])

		client.UserInfo.AuthAutoKey = authRsp.GetAuthSectResp().GetAutoAuthKey().GetBuffer()
		client.UserInfo.CliDBEncryptKey = authRsp.GetAuthSectResp().GetCliDBEncryptKey().GetBuffer()
		client.UserInfo.NewClientVersion = authRsp.GetAuthSectResp().GetNewVersion()
		client.UserInfo.UpdateFlag = authRsp.GetAuthSectResp().GetUpdateFlag()
		client.UserInfo.AuthResultFlag = authRsp.GetAuthSectResp().GetAuthResultFlag()

		// 保存账号信息
		accountRsp := authRsp.GetAcctSectResp()
		client.UserInfo.UserName = accountRsp.GetUsername()
		client.UserInfo.NickName = accountRsp.GetNickname()
		// account.userInfo.Password
		client.UserInfo.BindUin = accountRsp.GetBindUin()
		client.UserInfo.BindEmail = accountRsp.GetBindEmail()
		client.UserInfo.BindMobile = accountRsp.GetBindMobile()
		client.UserInfo.Alias = accountRsp.GetAlias()
		client.UserInfo.SafeDevice = accountRsp.GetSafeDevice()
	}

	return rsp.(*micromsg.UnifyAuthResponse), nil
}

// 检测登录二维码
func (client *WxClient) LogOut() (interface{}, error) {

	scene := &scene.NetSceneLogOut{
		UserInfo: client.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/logout",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.LogOutResponse), nil
}

// 获取用户配置信息
func (client *WxClient) GetProFile() (interface{}, error) {

	scene := &scene.NetSceneGetProfile{
		UserInfo: client.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/getprofile",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.GetProfileResponse), nil
}

// 初始化sync
func (client *WxClient) NewInit() (interface{}, error) {

	scene := &scene.NetSceneInit{
		UserInfo: client.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/newinit",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}
	client.UserInfo.SyncKey = rsp.(*micromsg.NewInitResponse).GetCurrentSynckey().GetBuffer()

	return rsp.(*micromsg.NewInitResponse), nil
}

// 初始化联系人列表
func (client *WxClient) InitContact(CurrentWxcontactSeq, CurrentChatRoomContactSeq int32) (interface{}, error) {

	scene := &scene.NetSceneInitContact{
		UserInfo:                  client.UserInfo,
		CurrentWxcontactSeq:       CurrentWxcontactSeq,
		CurrentChatRoomContactSeq: CurrentChatRoomContactSeq,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/initcontact",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.InitContactResponse), nil
}

// 发送消息
func (client *WxClient) SendMsgNew(ToId, Content string, Type, ClientMsgId uint32) (interface{}, error) {

	scene := &scene.NetSceneSendMsgNew{
		UserInfo:    client.UserInfo,
		Toid:        ToId,
		Content:     Content,
		Type:        Type,
		ClientMsgId: ClientMsgId,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/newsendmsg",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.NewSendMsgResponse), nil
}

// 发送图片
func (client *WxClient) SendImgMsg(ToId string, ImgPath string) (interface{}, error) {
	content, err := os.ReadFile(ImgPath)
	if err != nil {
		return nil, err
	}

	scene := &scene.NetSceneSendImgMsg{
		UserInfo:  client.UserInfo,
		Toid:      ToId,
		ImageData: content,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/uploadmsgimg",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.UploadMsgImgResponse), nil
}

// 心跳
func (client *WxClient) HeartBeat() (interface{}, error) {

	scene := &scene.NetSceneHeartBeat{
		UserInfo: client.UserInfo,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/heartbeat",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.HeartBeatResponse), nil
}

// 获取联系人信息
func (client *WxClient) GetContact(ContactWxid []string) (interface{}, error) {
	scene := &scene.NetSceneGetContact{
		UserInfo:  client.UserInfo,
		UserNames: ContactWxid,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/getcontact",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.GetContactResponse), nil
}

// 获取信息
func (client *WxClient) NewSync(sceneId uint32) (interface{}, error) {

	scene := &scene.NetSceneNewSync{
		UserInfo: client.UserInfo,
		Scene:    sceneId,
	}

	// 序列化
	request_data, err := scene.Req2Buf()
	if err != nil {
		return nil, err
	}

	// 请求
	response_data, err := client.UserInfo.GetServices().GetShortLink().Request(
		"/cgi-bin/micromsg-bin/newsync",
		request_data,
	)
	if err != nil {
		return nil, err
	}

	// 反序列化
	rsp, err := scene.Buf2Rsp(response_data)
	if err != nil {
		return nil, err
	}

	return rsp.(*micromsg.NewSyncResponse), nil
}
