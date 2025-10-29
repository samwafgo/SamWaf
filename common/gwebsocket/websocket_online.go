package gwebsocket

import (
	"crypto/rand"
	"errors"
	"fmt"
	Wssocket "github.com/gorilla/websocket"
	"sync"
	"time"
)

type WebSocketConnection struct {
	Conn      *Wssocket.Conn
	SessionID string
	UserKey   string
	CreatedAt time.Time
}

type WebSocketOnline struct {
	SocketMap    map[string]*WebSocketConnection // key: sessionID, value: connection
	UserSessions map[string][]string             // key: userKey, value: sessionIDs
	Mux          sync.Mutex                      //互斥锁
}

func InitWafWebSocket() *WebSocketOnline {
	wafWebsocket := &WebSocketOnline{
		SocketMap:    make(map[string]*WebSocketConnection),
		UserSessions: make(map[string][]string),
		Mux:          sync.Mutex{},
	}
	return wafWebsocket
}

// 生成唯一的会话ID
func (wafWebsocket *WebSocketOnline) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x-%d", bytes, time.Now().UnixNano())
}

// 添加WebSocket连接，返回会话ID
func (wafWebsocket *WebSocketOnline) AddWebSocket(userKey string, conn *Wssocket.Conn) string {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	sessionID := wafWebsocket.generateSessionID()

	// 创建连接对象
	wsConn := &WebSocketConnection{
		Conn:      conn,
		SessionID: sessionID,
		UserKey:   userKey,
		CreatedAt: time.Now(),
	}

	// 存储连接
	wafWebsocket.SocketMap[sessionID] = wsConn

	// 更新用户会话列表
	if sessions, exists := wafWebsocket.UserSessions[userKey]; exists {
		wafWebsocket.UserSessions[userKey] = append(sessions, sessionID)
	} else {
		wafWebsocket.UserSessions[userKey] = []string{sessionID}
	}

	return sessionID
}

// 兼容旧接口：设置WebSocket连接（会关闭同用户的其他连接）
func (wafWebsocket *WebSocketOnline) SetWebSocket(key string, value *Wssocket.Conn) {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	// 关闭该用户的所有现有连接
	if sessions, exists := wafWebsocket.UserSessions[key]; exists {
		for _, sessionID := range sessions {
			if wsConn, found := wafWebsocket.SocketMap[sessionID]; found {
				wsConn.Conn.Close()
				delete(wafWebsocket.SocketMap, sessionID)
			}
		}
		delete(wafWebsocket.UserSessions, key)
	}

	// 添加新连接
	sessionID := wafWebsocket.generateSessionID()
	wsConn := &WebSocketConnection{
		Conn:      value,
		SessionID: sessionID,
		UserKey:   key,
		CreatedAt: time.Now(),
	}

	wafWebsocket.SocketMap[sessionID] = wsConn
	wafWebsocket.UserSessions[key] = []string{sessionID}
}

// 根据会话ID获取WebSocket连接
func (wafWebsocket *WebSocketOnline) GetWebSocketBySession(sessionID string) *Wssocket.Conn {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	if wsConn, found := wafWebsocket.SocketMap[sessionID]; found {
		return wsConn.Conn
	}
	return nil
}

// 兼容旧接口：根据用户key获取WebSocket连接（返回第一个连接）
func (wafWebsocket *WebSocketOnline) GetWebSocket(key string) *Wssocket.Conn {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	if sessions, exists := wafWebsocket.UserSessions[key]; exists && len(sessions) > 0 {
		sessionID := sessions[0] // 返回第一个连接
		if wsConn, found := wafWebsocket.SocketMap[sessionID]; found {
			return wsConn.Conn
		}
	}
	return nil
}

// 获取用户的所有WebSocket连接
func (wafWebsocket *WebSocketOnline) GetUserWebSockets(userKey string) []*Wssocket.Conn {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	var connections []*Wssocket.Conn
	if sessions, exists := wafWebsocket.UserSessions[userKey]; exists {
		for _, sessionID := range sessions {
			if wsConn, found := wafWebsocket.SocketMap[sessionID]; found {
				connections = append(connections, wsConn.Conn)
			}
		}
	}
	return connections
}

func (wafWebsocket *WebSocketOnline) GetAllWebSocket() map[string]*Wssocket.Conn {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	// 创建一个副本，防止外部修改
	sockets := make(map[string]*Wssocket.Conn)
	for sessionID, wsConn := range wafWebsocket.SocketMap {
		sockets[sessionID] = wsConn.Conn
	}
	return sockets
}

// 根据会话ID删除WebSocket连接
func (wafWebsocket *WebSocketOnline) DelWebSocketBySession(sessionID string) error {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	wsConn, found := wafWebsocket.SocketMap[sessionID]
	if !found {
		return errors.New("未找到会话")
	}

	// 从会话映射中删除
	delete(wafWebsocket.SocketMap, sessionID)

	// 从用户会话列表中删除
	userKey := wsConn.UserKey
	if sessions, exists := wafWebsocket.UserSessions[userKey]; exists {
		newSessions := make([]string, 0)
		for _, sid := range sessions {
			if sid != sessionID {
				newSessions = append(newSessions, sid)
			}
		}
		if len(newSessions) > 0 {
			wafWebsocket.UserSessions[userKey] = newSessions
		} else {
			delete(wafWebsocket.UserSessions, userKey)
		}
	}

	return nil
}

// 兼容旧接口：删除用户的所有WebSocket连接
func (wafWebsocket *WebSocketOnline) DelWebSocket(key string) error {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	sessions, found := wafWebsocket.UserSessions[key]
	if !found {
		return errors.New("未找到数据")
	}

	// 删除所有会话
	for _, sessionID := range sessions {
		delete(wafWebsocket.SocketMap, sessionID)
	}
	delete(wafWebsocket.UserSessions, key)

	return nil
}
