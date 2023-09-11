package model

import (
	"errors"
	Wssocket "github.com/gorilla/websocket"
	"sync"
)

type WebSocketOnline struct {
	SocketMap map[string]*Wssocket.Conn
	Mux       sync.Mutex //互斥锁
}

func InitWafWebSocket() *WebSocketOnline {
	wafWebsocket := &WebSocketOnline{
		SocketMap: make(map[string]*Wssocket.Conn),
		Mux:       sync.Mutex{},
	}
	return wafWebsocket
}
func (wafWebsocket *WebSocketOnline) SetWebSocket(key string, value *Wssocket.Conn) {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()
	item, found := wafWebsocket.SocketMap[key]

	if found {
		item.Close()
		delete(wafWebsocket.SocketMap, key)
	}
	wafWebsocket.SocketMap[key] = value
}
func (wafWebsocket *WebSocketOnline) GetWebSocket(key string) *Wssocket.Conn {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()
	item, found := wafWebsocket.SocketMap[key]

	if found {
		return item
	} else {
		return nil
	}
}
func (wafWebsocket *WebSocketOnline) DelWebSocket(key string) error {
	wafWebsocket.Mux.Lock()
	defer wafWebsocket.Mux.Unlock()
	_, found := wafWebsocket.SocketMap[key]

	if found {
		delete(wafWebsocket.SocketMap, key)
		return nil
	} else {
		return errors.New("未找到数据")
	}
}
