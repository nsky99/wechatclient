package routes

import (
	"wechatclient/controllers"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	// 初始化 Gin 引擎
	router := gin.Default()

	// 登录
	login := router.Group("/v1/login")
	{
		login.POST("/getloginqrcode", controllers.GetLoginQrCode)
		login.POST("/checkloginqrcode", controllers.CheckLoginQrCode)
		login.POST("/secmanualauth", controllers.SecManualAuth)
		login.POST("/logout", controllers.LogOut)
		login.POST("/getprofile", controllers.GetProFile)
	}

	// 用户
	user := router.Group("/v1/user")
	{
		user.POST("/initcontact", controllers.InitContact)
		user.POST("/initcontactlist", controllers.InitContactList)
		user.POST("/getcontact", controllers.GetContact)
	}

	// 消息
	message := router.Group("/v1/message")
	{
		message.POST("/newinit", controllers.NewInit)
		message.POST("/sendmsgnew", controllers.SendMsgNew)
		message.POST("/sendimgmsg", controllers.SendImgMsg)
		// 转发cdn 视频UploadVideoRequest, "/cgi-bin/micromsg-bin/uploadvideo"
	}

	// 工具
	toosl := router.Group("/v1/tools")
	{
		toosl.POST("/heartbeat", controllers.HeartBeat)
	}
	return router
}
