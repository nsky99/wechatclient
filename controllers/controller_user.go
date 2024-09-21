package controllers

import (
	"net/http"
	"wechatclient/services"

	"github.com/gin-gonic/gin"
)

func InitContact(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	params := &struct {
		CurrentWxcontactSeq       int32 `json:"currentWxcontactSeq" validate:"required"`
		CurrentChatRoomContactSeq int32 `json:"currentChatRoomContactSeq" validate:"required"`
	}{}
	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.InitContact(sessionId, params.CurrentWxcontactSeq, params.CurrentChatRoomContactSeq)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func InitContactList(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.InitContactList(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func GetContact(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	params := &struct {
		ContactWxid []string `json:"contactWxid" validate:"required"`
	}{}
	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 最大只支持20个
	if len(params.ContactWxid) > 20 {
		params.ContactWxid = params.ContactWxid[:20]
	}

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.GetContact(sessionId, params.ContactWxid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
