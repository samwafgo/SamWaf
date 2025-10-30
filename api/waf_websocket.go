package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

type WafWebSocketApi struct {
}

func (w *WafWebSocketApi) WebSocketMessageApi(c *gin.Context) {
	var upGrader = websocket.Upgrader{
		Subprotocols: []string{c.Request.Header.Get("Sec-WebSocket-Protocol")},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		HandshakeTimeout: 45 * time.Second, // 握手超时时间
		ReadBufferSize:   1024,             // 读缓冲区大小
		WriteBufferSize:  1024,             // 写缓冲区大小
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

	// 设置WebSocket连接的读写超时
	ws.SetReadDeadline(time.Time{})  // 不设置读超时，保持长连接
	ws.SetWriteDeadline(time.Time{}) // 不设置写超时，保持长连接

	// 设置Pong处理器，用于心跳检测
	ws.SetPongHandler(func(string) error {
		zlog.Debug("收到pong消息，连接正常")
		return nil
	})

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

	// 生成用户标识和会话ID
	userKey := tokenInfo.BaseOrm.Tenant_ID + tokenInfo.BaseOrm.USER_CODE + tokenInfo.LoginAccount
	sessionID := global.GWebSocket.AddWebSocket(userKey, ws)

	zlog.Debug("WebSocket连接建立，用户: " + userKey + ", 会话ID: " + sessionID)

	defer func() {
		// 只关闭当前会话的连接
		websocket := global.GWebSocket.GetWebSocketBySession(sessionID)
		if websocket != nil {
			websocket.Close()
			global.GWebSocket.DelWebSocketBySession(sessionID)
		}
		zlog.Debug("WebSocket连接已关闭，会话ID: " + sessionID)
	}()

	for {
		//获取当前会话的WebSocket连接，检查是否存在
		wsConn := global.GWebSocket.GetWebSocketBySession(sessionID)
		if wsConn == nil {
			zlog.Debug("WebSocket连接已断开，退出消息循环，会话ID: " + sessionID)
			break
		}

		//读取ws中的数据
		mt, message, err := wsConn.ReadMessage()
		if err != nil {
			break
		}
		zlog.Debug("websocket msg=" + string(message) + ", 会话ID: " + sessionID)
		if string(message) == "ping" {
			message = []byte("pong")
		}

		//再次检查连接是否存在，避免写入时的竞态条件
		wsConn = global.GWebSocket.GetWebSocketBySession(sessionID)
		if wsConn == nil {
			zlog.Debug("WebSocket连接在处理消息时断开，会话ID: " + sessionID)
			break
		}

		//写入ws数据
		err = wsConn.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}
