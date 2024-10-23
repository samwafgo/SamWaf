package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"encoding/json"
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
		msgBytes, _ := json.Marshal(model.MsgPacket{
			MsgCode:    "-999",
			MsgCmdType: "Info",
		})
		err = ws.WriteMessage(1, msgBytes)
		zlog.Debug("无鉴权信息，请检查")
		return
	}
	global.GWebSocket.SetWebSocket(tokenInfo.BaseOrm.Tenant_ID+tokenInfo.BaseOrm.USER_CODE+tokenInfo.LoginAccount, ws)

	defer func() {
		websocket := global.GWebSocket.GetWebSocket(tokenInfo.BaseOrm.Tenant_ID + tokenInfo.BaseOrm.USER_CODE + tokenInfo.LoginAccount)
		if websocket != nil {
			websocket.Close()
			global.GWebSocket.DelWebSocket(tokenInfo.BaseOrm.Tenant_ID + tokenInfo.BaseOrm.USER_CODE + tokenInfo.LoginAccount)
		}
	}()

	for {
		//读取ws中的数据
		mt, message, err := global.GWebSocket.GetWebSocket(tokenInfo.BaseOrm.Tenant_ID + tokenInfo.BaseOrm.USER_CODE + tokenInfo.LoginAccount).ReadMessage()
		if err != nil {
			break
		}
		zlog.Debug("websocket msg=" + string(message))
		if string(message) == "ping" {
			message = []byte("pong")
		}
		//写入ws数据
		err = global.GWebSocket.GetWebSocket(tokenInfo.BaseOrm.Tenant_ID+tokenInfo.BaseOrm.USER_CODE+tokenInfo.LoginAccount).WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}
