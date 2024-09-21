package controllers

import (
	"net/http"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/services"

	"github.com/gin-gonic/gin"
)

// 登录需要携带的信息
// device_id
// device_type
// device_name
func GetLoginQrCode(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 解析参数
	params := &struct {
		DeviceID   string `json:"deviceId" validate:"required"`
		DeviceType string `json:"deviceType"`
		DeviceName string `json:"deviceName"`
	}{}

	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用服务的功能
	response, err := services.GetLoginQRCode(sessionId, params.DeviceID, params.DeviceType, params.DeviceName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "image/png", (response.(*micromsg.GetLoginQRCodeResponse)).GetQrcode().GetBuffer())
}

// 校验登录二维码
func CheckLoginQrCode(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能
	response, err := services.CheckLoginQRCode(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// 手动授权
func SecManualAuth(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能
	response, err := services.SecManualAuth(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// 退出
func LogOut(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.LogOut(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// 获取个人配置信息
func GetProFile(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.GetProFile(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
