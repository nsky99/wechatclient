package main

import "wechatclient/routes"

func init() {
	// 初始化缓存库
}

func main() {
	// 初始化 Gin 引擎
	router := routes.SetupRouter()

	// 启动 HTTP 服务器
	router.Run(":8080")
}
