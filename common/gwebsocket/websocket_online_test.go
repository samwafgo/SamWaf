package gwebsocket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	Wssocket "github.com/gorilla/websocket"
)

// 回归用例：管理端 WebSocket 曾经被多路 goroutine 同时裸写，触发
// gorilla/websocket 的 "concurrent write to websocket connection" panic。
//
// 线上栈（v1.3.23）：
//
//	api/waf_websocket.go:101 (ping 回显)  ← panic 点
//	同时还有 wafqueue/message_queue.go 与 waftask/task_delay_msg.go 在广播
//
// gorilla 只允许一个并发 writer（conn.go 里 isWriting 的 best-effort 检测）。
// 修复后写出口统一收敛到 SendToSession / Broadcast，内部按连接加锁串行化。
// 本用例复刻「多广播方 + 每连接回显」的并发形态，跑 go test -race 必须干净。
func TestConcurrentWrite_NoPanicNoRace(t *testing.T) {
	const (
		clientCount    = 4  // 同时打开的管理页签数
		broadcasters   = 4  // 广播方：消息队列 / 延迟消息任务 / 统计推送 ...
		broadcastTimes = 60 // 每个广播方推送轮数
		echoTimes      = 60 // 每个客户端 ping 次数
	)

	online := InitWafWebSocket()

	// 任何一路写入方 panic 都记下来，避免直接把测试进程打挂，方便看清是谁踩了谁
	var firstPanic atomic.Value
	guard := func(who string, f func()) {
		defer func() {
			if v := recover(); v != nil {
				firstPanic.CompareAndSwap(nil, fmt.Sprintf("%s: %v", who, v))
			}
		}()
		f()
	}

	upGrader := Wssocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	var echoSent int64
	var serverWG sync.WaitGroup
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		sessionID := online.AddWebSocket("tenant-user-admin", ws)

		serverWG.Add(1)
		defer func() {
			online.CloseSession(sessionID)
			serverWG.Done()
		}()

		// 复刻 api/waf_websocket.go 的回显循环：读到 ping 就原路写回 pong
		guard("echo("+sessionID[:8]+")", func() {
			for {
				mt, message, err := ws.ReadMessage()
				if err != nil {
					return
				}
				if string(message) == "ping" {
					message = []byte("pong")
				}
				if err = online.SendToSession(sessionID, mt, message); err != nil {
					return
				}
				atomic.AddInt64(&echoSent, 1)
			}
		})
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// 建立 N 条客户端连接，每条都开一个只管收的 goroutine（模拟浏览器正常消费）
	var received int64
	var clients []*Wssocket.Conn
	for i := 0; i < clientCount; i++ {
		c, _, err := Wssocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("第 %d 个客户端连接失败: %v", i, err)
		}
		clients = append(clients, c)
		go func(c *Wssocket.Conn) {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
				atomic.AddInt64(&received, 1)
			}
		}(c)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	// 等所有连接都注册进 SocketMap，保证广播能覆盖到
	deadline := time.Now().Add(3 * time.Second)
	for online.OnlineCount() < clientCount && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := online.OnlineCount(); got != clientCount {
		t.Fatalf("期望 %d 条在线连接，实际 %d", clientCount, got)
	}

	var wg sync.WaitGroup
	var broadcastSent int64

	// 写入方一：广播（wafqueue/message_queue.go、waftask/task_delay_msg.go 的写法）
	for b := 0; b < broadcasters; b++ {
		wg.Add(1)
		go func(b int) {
			defer wg.Done()
			payload := []byte(strings.Repeat(fmt.Sprintf("broadcast-%d;", b), 64))
			guard(fmt.Sprintf("broadcast(%d)", b), func() {
				for i := 0; i < broadcastTimes; i++ {
					atomic.AddInt64(&broadcastSent, int64(online.Broadcast(Wssocket.TextMessage, payload)))
					time.Sleep(time.Millisecond)
				}
			})
		}(b)
	}

	// 写入方二：客户端 ping，驱动服务端回显循环写同一条连接
	for _, c := range clients {
		wg.Add(1)
		go func(c *Wssocket.Conn) {
			defer wg.Done()
			for i := 0; i < echoTimes; i++ {
				if err := c.WriteMessage(Wssocket.TextMessage, []byte("ping")); err != nil {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}(c)
	}

	wg.Wait()

	if v := firstPanic.Load(); v != nil {
		t.Fatalf("并发写 WebSocket 触发 panic：%v", v)
	}

	// 广播期间不该有连接因为写失败被摘除
	if got := online.OnlineCount(); got != clientCount {
		t.Fatalf("并发写之后在线连接数应为 %d，实际 %d（说明有连接写失败被摘除）", clientCount, got)
	}

	// 一条不丢：服务端写成功多少条，客户端就该收到多少条
	wantTotal := atomic.LoadInt64(&broadcastSent) + atomic.LoadInt64(&echoSent)
	drainDeadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&received) < wantTotal && time.Now().Before(drainDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&received); got != wantTotal {
		t.Fatalf("服务端写成功 %d 条（广播 %d + 回显 %d），客户端只收到 %d 条",
			wantTotal, atomic.LoadInt64(&broadcastSent), atomic.LoadInt64(&echoSent), got)
	}

	for _, c := range clients {
		c.Close()
	}
	serverWG.Wait()
}

// 回归用例：客户端卡死不读时，写必须在 WriteWait 内超时返回，并把死连接摘掉。
//
// 老实现 api/waf_websocket.go 里是 SetWriteDeadline(time.Time{})「永不超时」，
// 一个半死的浏览器就能把广播方无限期吊在 isWriting=true 上，
// 把本来几十微秒的并发写窗口撑到秒级——这正是线上必现、本地不复现的根本原因。
func TestBroadcast_StalledClientTimesOutAndIsRemoved(t *testing.T) {
	online := InitWafWebSocket()

	upGrader := Wssocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	registered := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		registered <- online.AddWebSocket("tenant-user-admin", ws)
		select {}
	}))
	defer srv.Close()

	// 客户端连上之后完全不读，模拟卡死 / 掉线未察觉的浏览器
	client, _, err := Wssocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer client.Close()
	<-registered

	payload := []byte(strings.Repeat("y", 64*1024))
	start := time.Now()
	// 先把内核发送缓冲灌满（本机实测 2~3MB），再往后写就会卡住并触发写超时
	for i := 0; i < 4096; i++ {
		if online.Broadcast(Wssocket.TextMessage, payload) == 0 {
			break
		}
		if time.Since(start) > WriteWait+10*time.Second {
			t.Fatalf("写没有在 WriteWait(%v) 内超时，仍在持续写入", WriteWait)
		}
	}
	cost := time.Since(start)

	if online.OnlineCount() != 0 {
		t.Fatalf("卡死的连接应当被摘除，实际仍在线 %d 条", online.OnlineCount())
	}
	if cost > WriteWait+5*time.Second {
		t.Fatalf("卡死连接耗时 %v，超过预期上限（WriteWait=%v）", cost, WriteWait)
	}
	t.Logf("卡死客户端在 %v 内触发写超时并被摘除（WriteWait=%v）", cost, WriteWait)
}

// 会话表基本行为：加入 / 查询 / 摘除
func TestSessionLifecycle(t *testing.T) {
	online := InitWafWebSocket()

	upGrader := Wssocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	registered := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		registered <- online.AddWebSocket("same-user", ws)
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	var clients []*Wssocket.Conn
	var sessions []string
	for i := 0; i < 2; i++ {
		c, _, err := Wssocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("客户端连接失败: %v", err)
		}
		clients = append(clients, c)
		sessions = append(sessions, <-registered)
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	// 同一个用户开两个页签，应当是两条独立会话，互不顶掉
	if got := online.OnlineCount(); got != 2 {
		t.Fatalf("同用户两条连接应共存，实际在线 %d 条", got)
	}
	for _, sid := range sessions {
		if !online.HasSession(sid) {
			t.Fatalf("会话 %s 应当在线", sid)
		}
	}

	// 摘掉一条，另一条不受影响；重复摘除不应 panic
	online.CloseSession(sessions[0])
	online.CloseSession(sessions[0])
	if online.HasSession(sessions[0]) {
		t.Fatal("已关闭的会话不应还在表里")
	}
	if !online.HasSession(sessions[1]) {
		t.Fatal("另一条会话不应被误摘")
	}
	if got := online.OnlineCount(); got != 1 {
		t.Fatalf("期望剩 1 条在线，实际 %d", got)
	}

	// 向已摘除的会话发送应返回错误而不是 panic
	if err := online.SendToSession(sessions[0], Wssocket.TextMessage, []byte("x")); err == nil {
		t.Fatal("向已关闭会话发送应当返回错误")
	}
}
