package api

import (
	"SamWaf/global"
	"SamWaf/utils/zlog"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"net/http"
)

type WafWebSocketApi struct {
}

func (w *WafWebSocketApi) WebSocketMessageApi(c *gin.Context) {
	var upGrader = websocket.Upgrader{
		Subprotocols: []string{c.Request.Header.Get("Sec-WebSocket-Protocol")},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	//获取用户账号：
	tokenStr := c.GetHeader("Sec-WebSocket-Protocol")
	tokenInfo := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
	if tokenInfo.LoginAccount == "" {
		return
	}
	//升级get请求为webSocket协议
	ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	if global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount] == nil {
		global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount] = ws
	}

	defer func() {
		global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount].Close()
		global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount] = nil
	}()

	for {
		//读取ws中的数据
		mt, message, err := global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount].ReadMessage()
		if err != nil {
			break
		}
		zlog.Debug("websocket msg=" + string(message))
		if string(message) == "ping" {
			message = []byte("pong")
		}
		//写入ws数据
		err = global.GWebSocket[tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount].WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}
