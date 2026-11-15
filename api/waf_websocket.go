package api

import (
	"SamWaf/cache"
	"SamWaf/common/gwebsocket"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type WafWebSocketApi struct {
}

func (w *WafWebSocketApi) WebSocketMessageApi(c *gin.Context) {
	tokenStr := strings.TrimSpace(c.GetHeader("Sec-WebSocket-Protocol"))
	var tokenInfo model.TokenInfo
	if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_TOKEN+tokenStr, &tokenInfo); err != nil {
		if errors.Is(err, cache.ErrCacheBackend) {
			response.BackendUnavailableWithMessage("服务暂时不可用，请稍后重试", c)
		} else {
			response.AuthFailWithMessage("登录状态已失效，请重新登录", c)
		}
		return
	}
	validate := func() error {
		_, err := wafTokenInfoService.ValidateSession(tokenInfo, tokenStr)
		return err
	}
	ws, err := upgradeAccountWebSocket(c)
	if err != nil {
		zlog.Error("websocketinit", err)
		return
	}
	serveAccountWebSocket(ws, global.GWebSocket, tokenInfo, c.Query("keyid"), validate, gwebsocket.PingPeriod)
}

func serveAccountWebSocket(ws *websocket.Conn, online *gwebsocket.WebSocketOnline, tokenInfo model.TokenInfo, keyID string, validate func() error, checkPeriod time.Duration) {
	ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))
	})

	// 登记后的持久会话校验完成前，连接不参与消息推送。
	sessionID, err := online.AddValidatedAccountWebSocket(tokenInfo.Tenant_ID, tokenInfo.USER_CODE, tokenInfo.LoginAccount, keyID, ws, validate)
	if err != nil {
		return
	}
	zlog.Debug("WebSocket连接建立，会话ID: " + sessionID)

	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(checkPeriod)
		defer ticker.Stop()
		defer online.CloseSession(sessionID)
		for {
			select {
			case <-stopPing:
				return
			case <-ticker.C:
				// 会话校验与心跳共用周期；仅会话失效才关闭连接，
				// 存储暂时不可用时保留连接，下一轮再复核。
				if err := validate(); err != nil {
					if errors.Is(err, waf_service.ErrSessionBackend) {
						continue
					}
					return
				}
				if err := online.PingSession(sessionID); err != nil {
					return
				}
			}
		}
	}()

	defer func() {
		close(stopPing)
		online.CloseSession(sessionID)
		zlog.Debug("WebSocket连接已关闭，会话ID: " + sessionID)
	}()

	for {
		mt, message, err := ws.ReadMessage()
		if err != nil {
			return
		}
		ws.SetReadDeadline(time.Now().Add(gwebsocket.PongWait))
		if string(message) == "ping" {
			message = []byte("pong")
		}
		if err := online.SendToSession(sessionID, mt, message); err != nil {
			return
		}
	}
}

func upgradeAccountWebSocket(c *gin.Context) (*websocket.Conn, error) {
	upGrader := websocket.Upgrader{
		Subprotocols: []string{c.Request.Header.Get("Sec-WebSocket-Protocol")},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		HandshakeTimeout: 45 * time.Second,
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
	}
	return upGrader.Upgrade(c.Writer, c.Request, nil)
}
