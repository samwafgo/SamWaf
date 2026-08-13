package gwebsocket

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	Wssocket "github.com/gorilla/websocket"
)

// gorilla/websocket 只允许「一个并发 reader + 一个并发 writer」。
// 历史实现把裸 *websocket.Conn 交给外部（消息队列 / 定时任务 / ping 回显）各写各的，
// 撞在一起就会触发 "concurrent write to websocket connection" panic。
//
// 现在写出口全部收敛到本包：外部只能拿到会话 ID，通过 SendToSession / Broadcast 发送，
// 内部按连接加锁串行化，并且强制写超时——避免一个卡死的客户端把广播方无限期吊住。
const (
	// WriteWait 单次写的最长等待时间。客户端卡死时最多把发送方挂住这么久。
	WriteWait = 5 * time.Second
	// PingPeriod 服务端主动发 Ping 的间隔。
	PingPeriod = 30 * time.Second
	// PongWait 读超时。超过这个时间既没收到业务消息也没收到 Pong，就认定连接已死。
	PongWait = 90 * time.Second
)

type WebSocketConnection struct {
	Conn      *Wssocket.Conn
	SessionID string
	UserKey   string
	CreatedAt time.Time

	writeMux sync.Mutex // 该连接的写出口互斥锁，禁止并发写
}

// SafeWriteMessage 串行化写入 + 写超时，是本包对外唯一的数据帧写入方式
func (wsConn *WebSocketConnection) SafeWriteMessage(messageType int, data []byte) error {
	wsConn.writeMux.Lock()
	defer wsConn.writeMux.Unlock()

	if err := wsConn.Conn.SetWriteDeadline(time.Now().Add(WriteWait)); err != nil {
		return err
	}
	return wsConn.Conn.WriteMessage(messageType, data)
}

// SafePing 发送控制帧 Ping。
// gorilla 的 WriteControl 允许与其他方法并发调用，所以这里刻意不抢写锁，
// 否则一次卡住的数据帧写入会把心跳也拖死，反而没法探活。
func (wsConn *WebSocketConnection) SafePing() error {
	return wsConn.Conn.WriteControl(Wssocket.PingMessage, nil, time.Now().Add(WriteWait))
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

// getSession 取出会话对象（内部用，外部拿不到裸连接）
func (wafWebsocket *WebSocketOnline) getSession(sessionID string) *WebSocketConnection {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	return wafWebsocket.SocketMap[sessionID]
}

// snapshot 复制一份当前在线连接，写入动作在锁外进行，
// 避免一次慢写把整张表锁住导致新连接注册不进来
func (wafWebsocket *WebSocketOnline) snapshot() []*WebSocketConnection {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	conns := make([]*WebSocketConnection, 0, len(wafWebsocket.SocketMap))
	for _, wsConn := range wafWebsocket.SocketMap {
		conns = append(conns, wsConn)
	}
	return conns
}

// HasSession 会话是否还在线
func (wafWebsocket *WebSocketOnline) HasSession(sessionID string) bool {
	return wafWebsocket.getSession(sessionID) != nil
}

// OnlineCount 当前在线连接数
func (wafWebsocket *WebSocketOnline) OnlineCount() int {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	return len(wafWebsocket.SocketMap)
}

// SendToSession 向指定会话发送消息
func (wafWebsocket *WebSocketOnline) SendToSession(sessionID string, messageType int, data []byte) error {
	wsConn := wafWebsocket.getSession(sessionID)
	if wsConn == nil {
		return errors.New("未找到会话")
	}
	return wsConn.SafeWriteMessage(messageType, data)
}

// Broadcast 广播给所有在线连接，返回发送成功的连接数。
// 写失败的连接直接关闭并摘除：死连接留在表里只会让后续每一轮广播都白等一次写超时。
func (wafWebsocket *WebSocketOnline) Broadcast(messageType int, data []byte) int {
	successCount := 0
	for _, wsConn := range wafWebsocket.snapshot() {
		if wsConn == nil {
			continue
		}
		if err := wsConn.SafeWriteMessage(messageType, data); err != nil {
			wafWebsocket.CloseSession(wsConn.SessionID)
			continue
		}
		successCount++
	}
	return successCount
}

// PingAll 给所有在线连接发心跳，失败的连接摘除
func (wafWebsocket *WebSocketOnline) PingAll() {
	for _, wsConn := range wafWebsocket.snapshot() {
		if wsConn == nil {
			continue
		}
		if err := wsConn.SafePing(); err != nil {
			wafWebsocket.CloseSession(wsConn.SessionID)
		}
	}
}

// PingSession 给指定会话发心跳
func (wafWebsocket *WebSocketOnline) PingSession(sessionID string) error {
	wsConn := wafWebsocket.getSession(sessionID)
	if wsConn == nil {
		return errors.New("未找到会话")
	}
	return wsConn.SafePing()
}

// CloseSession 关闭并摘除指定会话（可重复调用）
func (wafWebsocket *WebSocketOnline) CloseSession(sessionID string) {
	wafWebsocket.Mux.Lock()
	wsConn, found := wafWebsocket.SocketMap[sessionID]
	if found {
		wafWebsocket.removeSessionLocked(sessionID, wsConn.UserKey)
	}
	wafWebsocket.Mux.Unlock()

	if found {
		// Close 与其他方法并发调用是安全的，放在锁外做，避免阻塞其他会话
		wsConn.Conn.Close()
	}
}

// 根据会话ID删除WebSocket连接
func (wafWebsocket *WebSocketOnline) DelWebSocketBySession(sessionID string) error {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()

	wsConn, found := wafWebsocket.SocketMap[sessionID]
	if !found {
		return errors.New("未找到会话")
	}

	wafWebsocket.removeSessionLocked(sessionID, wsConn.UserKey)
	return nil
}

// removeSessionLocked 从两张表里摘除会话，调用方需持有 Mux
func (wafWebsocket *WebSocketOnline) removeSessionLocked(sessionID string, userKey string) {
	delete(wafWebsocket.SocketMap, sessionID)

	sessions, exists := wafWebsocket.UserSessions[userKey]
	if !exists {
		return
	}
	newSessions := make([]string, 0, len(sessions))
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
