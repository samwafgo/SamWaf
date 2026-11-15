package gwebsocket

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	Wssocket "github.com/gorilla/websocket"
)

func TestCloseAccountSessionsOnlyMatchingScope(t *testing.T) {
	online := InitWafWebSocket()

	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		tenantID := r.URL.Query().Get("tenant")
		userCode := r.URL.Query().Get("user")
		login := r.URL.Query().Get("login")
		<-ready
		_, err = online.AddValidatedAccountWebSocket(tenantID, userCode, login, "", ws, func() error { return nil })
		if err != nil {
			return
		}
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	dial := func(query string) *Wssocket.Conn {
		t.Helper()
		conn, _, err := Wssocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+query, nil)
		if err != nil {
			t.Fatalf("连接失败(%s): %v", query, err)
		}
		return conn
	}
	target1 := dial("?tenant=t&user=u&login=admin")
	defer target1.Close()
	target2 := dial("?tenant=t&user=u&login=admin")
	defer target2.Close()
	sameLoginOtherTenant := dial("?tenant=t2&user=u&login=admin")
	defer sameLoginOtherTenant.Close()
	sameScopeOtherLogin := dial("?tenant=t&user=u&login=other")
	defer sameScopeOtherLogin.Close()

	close(ready)
	deadline := time.Now().Add(3 * time.Second)
	for online.OnlineCount() < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := online.OnlineCount(); got != 4 {
		t.Fatalf("期望 4 条在线连接，实际 %d", got)
	}

	if got := online.CloseAccountSessions("t", "u", "admin"); got != 2 {
		t.Fatalf("应关闭 2 条目标连接，实际 %d", got)
	}
	if got := online.CloseAccountSessions("t", "u", "admin"); got != 0 {
		t.Fatalf("重复关闭不应再有连接，实际 %d", got)
	}

	for _, conn := range []*Wssocket.Conn{target1, target2} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := conn.ReadMessage(); err == nil {
			t.Fatal("目标账号连接应已关闭")
		}
	}
	if got := online.OnlineCount(); got != 2 {
		t.Fatalf("应只剩 2 条其它账号连接，实际 %d", got)
	}
	if got := online.UserSessions[accountUserKey("t2", "u", "admin")]; len(got) != 1 {
		t.Fatalf("不同租户的同账号连接不应被关闭，实际 %d 条", len(got))
	}
	if got := online.UserSessions[accountUserKey("t", "u", "other")]; len(got) != 1 {
		t.Fatalf("同范围不同账号的连接不应被关闭，实际 %d 条", len(got))
	}
}

func TestValidatedConnectionBlocksBroadcastUntilRegistered(t *testing.T) {
	online := InitWafWebSocket()
	release := make(chan struct{})
	registered := make(chan string, 1)

	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		sid, err := online.AddValidatedAccountWebSocket("t", "u", "admin", "", ws, func() error {
			<-release
			return nil
		})
		if err != nil {
			registered <- ""
			return
		}
		registered <- sid
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	conn, _, err := Wssocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for online.pendingCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := online.pendingCount(); got != 1 {
		t.Fatalf("登记中的连接应先进入连接表，实际 %d 条", got)
	}
	if got := online.Broadcast(Wssocket.TextMessage, []byte("pending")); got != 0 {
		t.Fatalf("登记校验完成前不应广播，实际发出 %d 条", got)
	}
	close(release)
	sid := <-registered
	if sid == "" {
		t.Fatal("账号连接登记失败")
	}
	if !online.HasSession(sid) {
		t.Fatal("校验通过后连接应完成登记")
	}
	if got := online.Broadcast(Wssocket.TextMessage, []byte("ready")); got != 1 {
		t.Fatalf("登记校验完成后应可广播，实际发出 %d 条", got)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil || string(data) != "ready" {
		t.Fatalf("应收到校验后的消息: data=%q err=%v", data, err)
	}
}

func TestAddValidatedAccountWebSocketFailsValidationClosesAndUnregisters(t *testing.T) {
	online := InitWafWebSocket()
	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	closed := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		_, _ = online.AddValidatedAccountWebSocket("t", "u", "admin", "", ws, func() error {
			return errors.New("会话未生效")
		})
		closed <- struct{}{}
	}))
	defer srv.Close()

	conn, _, err := Wssocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()
	<-closed
	if got := online.OnlineCount(); got != 0 {
		t.Fatalf("校验失败的连接应已摘除，实际在线 %d 条", got)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("校验失败的连接应已关闭")
	}
}
