package api

import (
	"SamWaf/common/gwebsocket"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	Wssocket "github.com/gorilla/websocket"
)

func dialUpgradedAccountConn(t *testing.T) (client, server *Wssocket.Conn) {
	t.Helper()
	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upgraded := make(chan *Wssocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		upgraded <- ws
		select {}
	}))
	t.Cleanup(srv.Close)

	conn, _, err := Wssocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, <-upgraded
}

func TestServeAccountWebSocketSessionValidationBlocksConnection(t *testing.T) {
	online := gwebsocket.InitWafWebSocket()
	client, serverWS := dialUpgradedAccountConn(t)
	defer serverWS.Close()

	validate := func() error { return errors.New("会话未生效") }
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAccountWebSocket(serverWS, online, model.TokenInfo{BaseOrm: baseorm.BaseOrm{Tenant_ID: "t", USER_CODE: "u"}, LoginAccount: "admin"}, "", validate, time.Hour)
	}()
	<-done

	if got := online.OnlineCount(); got != 0 {
		t.Fatalf("持久会话校验未通过的连接不应登记，实际在线 %d 条", got)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := client.ReadMessage(); err == nil {
		t.Fatal("持久会话校验未通过的连接应已关闭")
	}
}

func TestServeAccountWebSocketCloseAccountStopsValidatedConnection(t *testing.T) {
	online := gwebsocket.InitWafWebSocket()
	_, serverWS := dialUpgradedAccountConn(t)
	defer serverWS.Close()
	validate := func() error { return nil }

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAccountWebSocket(serverWS, online, model.TokenInfo{BaseOrm: baseorm.BaseOrm{Tenant_ID: "t", USER_CODE: "u"}, LoginAccount: "admin"}, "", validate, time.Hour)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for online.OnlineCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := online.CloseAccountSessions("t", "u", "admin"); got != 1 {
		t.Fatalf("应关闭 1 条目标账号连接，实际 %d", got)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("账号连接被关闭后，处理循环应退出")
	}
	if got := online.OnlineCount(); got != 0 {
		t.Fatalf("目标账号会话应全部下线，实际在线 %d 条", got)
	}
}
