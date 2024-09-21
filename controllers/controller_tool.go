package controllers

import (
	"net/http"
	"wechatclient/services"

	"github.com/gin-gonic/gin"
)

func HeartBeat(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.HeartBeat(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
