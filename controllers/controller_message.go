package controllers

import (
	"net/http"
	"wechatclient/services"

	"github.com/gin-gonic/gin"
)

func NewInit(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.NewInit(sessionId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func SendMsgNew(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	params := &struct {
		ToId        string `json:"toid" validate:"required"`
		Content     string `json:"content" validate:"required"`
		Type        uint32 `json:"type" validate:"required"`
		ClientMsgId uint32 `json:"clientMsgId" validate:"required"`
	}{}

	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	// 1  发送文件
	// 42 发送名片
	// <?xml version="1.0"?><msg bigheadimgurl="" smallheadimgurl="" username="wxid_16bims1c5ufg22" nickname="nsky" fullpy="nsky" shortpy="" alias="zhl17681097599" imagestatus="2" scene="17" province="安徽" city="中国大陆" sign="" sex="1" certflag="0" certinfo="" brandIconUrl="" brandHomeUrl="" brandSubscriptConfigUrl= "" brandFlags="0" regionCode="CN_Anhui_Fuyang" />
	response, err := services.SendMsgNew(sessionId, params.ToId, params.Content, params.Type, params.ClientMsgId)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func SendImgMsg(c *gin.Context) {
	sessionId, _ := c.GetQuery("sessionId")

	params := &struct {
		ToId    string `json:"toid" validate:"required"`
		ImgPath string `json:"imgPath" validate:"required"`
	}{}

	if err := c.ShouldBindJSON(&params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用服务的功能- 通过sessionid找到绑定的微信客户端进而调用微信功能
	response, err := services.SendImgMsg(sessionId, params.ToId, params.ImgPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}
