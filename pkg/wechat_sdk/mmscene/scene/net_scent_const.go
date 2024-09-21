package scene

// 短链接
const (
	// /cgi-bin/micromsg-bin/favsync | | 支持长连接 | need auth
	ReportArgSearchContact                = 106  // 搜索联系人
	ReportArgUploadMsgImg                 = 110  // 转发cdn图片
	ReportArgCreateChatRoom               = 119  // 创建群聊
	ReportArgAddChatRoomMember            = 120  // 邀请好友进群
	ReportArgNewSync                      = 138  // /cgi-bin/micromsg-bin/newsync | 同步消息 | 支持长连接 | need auth
	ReportArgNewInit                      = 139  // /cgi-bin/micromsg-bin/newinit
	ReportArgGetQrCode                    = 168  // 获取群/个人二维码
	ReportArgSendEmoji                    = 175  // /cgi-bin/micromsg-bin/sendemoji | 发送表情包 | 支持长连接 | need auth
	ReportArgDelChatRoomMember            = 179  // 移除群成员
	ReportArgGetContact                   = 182  // /cgi-bin/micromsg-bin/getcontact | 获取联系人信息 | 支持长连接 | need auth
	ReportArgSendAppMsg                   = 222  // /cgi-bin/micromsg-bin/sendappmsg | 发送app 消息 | 支持长连接 | need auth
	ReportArgStatusNotify                 = 251  // /cgi-bin/micromsg-bin/statusnotify | 状态通知 | 不支持长连接 | need auth
	ReportArgSecManualAuth                = 252  // /cgi-bin/micromsg-bin/secmanualauth | 安全认证 | 支持长连接 | no auth
	ReportArgLogout                       = 282  // /cgi-bin/micromsg-bin/logout | 退出登录 | 支持长连接 | need auth
	ReportArgGetProfile                   = 302  // /cgi-bin/micromsg-bin/getprofile | 获取登录二维码 | 支持长连接 | need auth
	ReportArgGetLoginQrCode               = 502  // /cgi-bin/micromsg-bin/getloginqrcode | 获取登录二维码 | 支持长连接 | no auth
	ReportArgCheckLoginQrCode             = 503  // /cgi-bin/micromsg-bin/checkloginqrcode | 检测登录二维码 | 支持长连接 | no auth
	ReportArgHeartBeat                    = 518  // /cgi-bin/micromsg-bin/heartbeat | 心跳 | 支持长连接 | need auth
	ReportArgSendMsgNew                   = 522  // /cgi-bin/micromsg-bin/newsendmsg | 发送消息 | 支持长连接 | need auth
	ReportArgBatchEmojiDownload           = 697  // /cgi-bin/micromsg-bin/mmbatchemojidownload | 批量下载表情包 | 不支持长连接 | need auth
	ReportArgReportClientCheck            = 771  // /cgi-bin/micromsg-bin/reportclientcheck | 上报客户端校验数据 | 不支持长连接 | need auth
	ReportArgInitContact                  = 851  // /cgi-bin/micromsg-bin/initcontact | 初始化联系人列表 | 不支持长连接 | need auth
	ReportArgTransferChatRoomOwnerRequest = 990  // 转让群
	ReportArgSendFileUploadMsg            = 6691 // /cgi-bin/micromsg-bin/sendfileuploadmsg | 发送文件 | 不支持长连接 | need auth
)

// 长链接
const (
	CmdInvalid            = 0
	CmdIdUploadMsgImg     = 9   //
	CmdIdUploadVoice      = 19  //
	CmdIdNewSync          = 26  // 异步同步消息
	CmdIdInit             = 27  //
	CmdIdUploadVideo      = 39  //
	CmdIdSendEmoji        = 68  // 发送表情包
	CmdIdGetContact       = 71  //
	CmdIdSendAppMsg       = 107 // 发送小程序
	CmdIdGetProfile       = 118 //
	CmdIdLogout           = 133 //
	CmdIdFavSync          = 195 //
	CmdIdGetLoginQrCode   = 232 //
	CmdIdCheckLoginQrCode = 233 //
	CmdIdSendMsgNew       = 237 //
	CmdIdHeartBeat        = 238 //
	CmdIdManualAuth       = 253 //
	CmdIdSecManualAuth    = 433 //
)

// 登录二维码的状态
const (
	LoginQrcodeStateNone   uint32 = 0 // 登陆二维码状态：未空状态
	LoginQrcodeStateScaned uint32 = 1 // 登陆二维码状态：扫描
	LoginQrcodeStateSure   uint32 = 2 // 登陆二维码状态：点击了确定登陆
	LoginQrcodeStateCancl  uint32 = 4 // 登陆二维码状态：扫描并取消
)

// 发送消息的类型
const (
	SendMsgTypeText         uint32 = 1     // 消息类型：文本消息
	SendMsgTypeImage        uint32 = 3     // 消息类型：图片消息
	SendMsgTypeCard         uint32 = 42    // 消息类型：名片
	SendMsgTypeRefer        uint32 = 49    // 消息类型：引用
	SendMsgTypeStatusNotify uint32 = 51    // 消息类型：状态通知
	SendMsgTypeSystemMsg    uint32 = 10002 // 消息类型：系统消息
)

const (
	SyncMsgDigestTypeLongLink  uint32 = 0 // 长链接同步
	SyncMsgDigestTypeShortLink uint32 = 1 // 短链接同步
)
