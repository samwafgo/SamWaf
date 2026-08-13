package api

import (
	"SamWaf/common/gwebsocket"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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

	if tokenInfo.LoginAccount == "" {
		//写入ws数据（此时连接还没登记到管理器，只有当前协程在写）
		msgBytes, _ := json.Marshal(model.MsgPacket{
			MsgCode:    "-999",
			MsgCmdType: "Info",
		})
		ws.SetWriteDeadline(time.Now().Add(gwebsocket.WriteWait))
		err = ws.WriteMessage(websocket.TextMessage, msgBytes)
		zlog.Debug("无鉴权信息，请检查")
		ws.Close() // 未鉴权连接必须显式关闭，否则连接一直挂着不释放
		return
	}

	// 读超时靠心跳续期：前端每 30s 发一次 ping，服务端也会主动发 Ping 帧，
	// 只要有一路活着就会刷新 deadline；都没了说明连接已死，读取直接报错退出。
	ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))
	ws.SetPongHandler(func(string) error {
		zlog.Debug("收到pong消息，连接正常")
		return ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))
	})

	// 生成用户标识和会话ID
	userKey := tokenInfo.BaseOrm.Tenant_ID + tokenInfo.BaseOrm.USER_CODE + tokenInfo.LoginAccount
	sessionID := global.GWebSocket.AddWebSocket(userKey, ws)

	zlog.Debug("WebSocket连接建立，用户: " + userKey + ", 会话ID: " + sessionID)

	// 服务端主动心跳：探活半开连接，同时给读超时续期
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(gwebsocket.PingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-ticker.C:
				if err := global.GWebSocket.PingSession(sessionID); err != nil {
					return
				}
			}
		}
	}()

	defer func() {
		close(stopPing)
		// 只关闭当前会话的连接
		global.GWebSocket.CloseSession(sessionID)
		zlog.Debug("WebSocket连接已关闭，会话ID: " + sessionID)
	}()

	for {
		//读取ws中的数据（每条连接只有这一个读协程）
		mt, message, err := ws.ReadMessage()
		if err != nil {
			break
		}
		ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))

		zlog.Debug("websocket msg=" + string(message) + ", 会话ID: " + sessionID)
		if string(message) == "ping" {
			message = []byte("pong")
		}

		//写入ws数据：统一走会话管理器，内部按连接加锁，避免与队列/定时任务的广播并发写
		if err = global.GWebSocket.SendToSession(sessionID, mt, message); err != nil {
			zlog.Debug("WebSocket回写失败，退出消息循环，会话ID: " + sessionID)
			break
		}
	}
}
