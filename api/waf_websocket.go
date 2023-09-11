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

	//升级get请求为webSocket协议
	ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		zlog.Error("websocketinit", err)
		return
	}
	if tokenInfo.LoginAccount == "" {
		//写入ws数据
		err = ws.WriteMessage(1, []byte("授权失败"))
		zlog.Info("无鉴权信息，请检查")
		return
	}
	global.GWebSocket.SetWebSocket(tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount, ws)

	defer func() {
		websocket := global.GWebSocket.GetWebSocket(tokenInfo.TenantId + tokenInfo.UserCode + tokenInfo.LoginAccount)
		if websocket != nil {
			websocket.Close()
			global.GWebSocket.DelWebSocket(tokenInfo.TenantId + tokenInfo.UserCode + tokenInfo.LoginAccount)
		}
	}()

	for {
		//读取ws中的数据
		mt, message, err := global.GWebSocket.GetWebSocket(tokenInfo.TenantId + tokenInfo.UserCode + tokenInfo.LoginAccount).ReadMessage()
		if err != nil {
			break
		}
		zlog.Debug("websocket msg=" + string(message))
		if string(message) == "ping" {
			message = []byte("pong")
		}
		//写入ws数据
		err = global.GWebSocket.GetWebSocket(tokenInfo.TenantId+tokenInfo.UserCode+tokenInfo.LoginAccount).WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}
