package wafenginecore

import (
	"SamWaf/global"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 端到端计数：起真实 http 服务器，把 attachTrafficMeter 挂上去，
// 断言「记到的字节」与「实际收发的字节」逐一对齐。
// 覆盖的正是老实现记不到的那些路径：静态大文件、chunked、流式、被拦截响应、WebSocket。

// tmServe 起一个挂了计量的测试服务器；done 在 handler 结账后关闭
func tmServe(hostCode string, h http.HandlerFunc) (*httptest.Server, <-chan struct{}) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw, settle := attachTrafficMeter(w, r, hostCode, r.Host)
		defer close(done) // 后注册先执行：settle 先跑完再放行断言
		defer settle()
		h(cw, r)
	}))
	return srv, done
}

// 静态大文件：老实现里这类请求连日志都不记，字节全丢（issue #930 主因）
func TestTrafficE2E_StaticFileServeFile(t *testing.T) {
	global.DrainTraffic()

	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	const size = 5 << 20 // 5MB
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), size), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, done := tmServe("static", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	})
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if n != size {
		t.Fatalf("客户端收到 %d 字节，期望 %d", n, size)
	}
	_, out := tmDrain("static")
	if out != size {
		t.Fatalf("静态大文件出站计数 = %d，期望 %d（差 %d 字节）", out, size, size-out)
	}
}

// HEAD 请求没有响应体，出站应为 0（不能把 Content-Length 当成已发送字节）
func TestTrafficE2E_HeadHasNoBody(t *testing.T) {
	global.DrainTraffic()

	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte("B"), 100000), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, done := tmServe("head", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	})
	defer srv.Close()

	req, _ := http.NewRequest("HEAD", srv.URL+"/f.bin", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if _, out := tmDrain("head"); out != 0 {
		t.Fatalf("HEAD 出站计数 = %d，期望 0", out)
	}
}

// chunked：Content-Length 是 -1，老实现只能记 0
func TestTrafficE2E_ChunkedResponse(t *testing.T) {
	global.DrainTraffic()

	srv, done := tmServe("chunk", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain") // 不设 Content-Length → chunked
		for i := 0; i < 5; i++ {
			w.Write(bytes.Repeat([]byte("x"), 1000))
			w.(http.Flusher).Flush()
		}
	})
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != -1 {
		t.Fatalf("前置假设失败：期望 chunked(ContentLength=-1)，实际 %d", resp.ContentLength)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	_, out := tmDrain("chunk")
	if n != 5000 || out != 5000 {
		t.Fatalf("chunked：客户端收到 %d，计数 %d，期望都是 5000", n, out)
	}
}

// SSE 流式：每次 Flush 都要能算进去，且 Flush 必须真的透传（否则客户端收不到）
func TestTrafficE2E_SSEStreaming(t *testing.T) {
	global.DrainTraffic()

	const events = 10
	const oneEvent = "data: 00\n\n"
	srv, done := tmServe("sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("SSE 场景拿不到 Flusher")
			return
		}
		for i := 0; i < events; i++ {
			fmt.Fprintf(w, "data: %02d\n\n", i)
			f.Flush()
		}
	})
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// 逐事件读，验证确实是流式推送而不是一次性缓冲
	br := bufio.NewReader(resp.Body)
	got := 0
	for i := 0; i < events; i++ {
		line, err := br.ReadString(byte('\n'))
		if err != nil {
			t.Fatalf("第 %d 个事件读取失败: %v", i, err)
		}
		if strings.HasPrefix(line, "data: ") {
			got++
		}
		br.ReadString(byte('\n')) // 事件之间的空行
	}
	io.Copy(io.Discard, br)
	resp.Body.Close()
	<-done

	if got != events {
		t.Fatalf("只收到 %d 个事件，期望 %d", got, events)
	}
	want := int64(events * len(oneEvent))
	if _, out := tmDrain("sse"); out != want {
		t.Fatalf("SSE 出站计数 = %d，期望 %d", out, want)
	}
}

// 被 WAF 拦截的响应（403 + 拦截页）同样要计入出站
func TestTrafficE2E_BlockedResponseCounted(t *testing.T) {
	global.DrainTraffic()

	page := []byte("<html><body>403 blocked by SamWaf</body></html>")
	srv, done := tmServe("blocked", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write(page)
	})
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	if resp.StatusCode != 403 {
		t.Fatalf("状态码 = %d", resp.StatusCode)
	}
	if _, out := tmDrain("blocked"); out != int64(len(page)) {
		t.Fatalf("拦截页出站计数 = %d，期望 %d", out, len(page))
	}
}

// 上传：入站按「真实读到的字节」计
func TestTrafficE2E_UploadBody(t *testing.T) {
	global.DrainTraffic()

	const size = 1 << 20
	srv, done := tmServe("upload", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	})
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL, "application/octet-stream", bytes.NewReader(make([]byte, size)))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	in, _ := tmDrain("upload")
	if in != size {
		t.Fatalf("上传入站计数 = %d，期望 %d", in, size)
	}
}

// chunked 上传（Content-Length 未知）：老实现取 r.ContentLength = -1 会把入站流量算成负数
func TestTrafficE2E_ChunkedUpload(t *testing.T) {
	global.DrainTraffic()

	const size = 300000
	srv, done := tmServe("chunkup", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != -1 {
			t.Errorf("前置假设失败：期望 chunked 上传 ContentLength=-1，实际 %d", r.ContentLength)
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	})
	defer srv.Close()

	pr, pw := io.Pipe()
	go func() {
		pw.Write(make([]byte, size))
		pw.Close()
	}()
	req, _ := http.NewRequest("POST", srv.URL, pr) // body 长度未知 → chunked
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	in, _ := tmDrain("chunkup")
	if in != size {
		t.Fatalf("chunked 上传入站计数 = %d，期望 %d（且必须为正数）", in, size)
	}
}

// 口径边界（有意为之，用例锁住行为）：只统计业务真正读到的请求体。
// 请求被提前拒绝、body 没被读走时，这部分字节不计入入站。
func TestTrafficE2E_UnreadBodyNotCounted(t *testing.T) {
	global.DrainTraffic()

	srv, done := tmServe("unread", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403) // 直接拒绝，不读 body
	})
	defer srv.Close()

	resp, err := srv.Client().Post(srv.URL, "application/octet-stream", bytes.NewReader(make([]byte, 65536)))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-done

	in, _ := tmDrain("unread")
	if in != 0 {
		t.Fatalf("未读取的请求体不计入入站，实际计到 %d", in)
	}
}

// WebSocket 之类的协议升级：劫持之后的隧道字节必须双向计数，且连接不能被包装层弄坏
func TestTrafficE2E_HijackedConnectionCounted(t *testing.T) {
	global.DrainTraffic()

	const respHead = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	const serverPush = "server-frame-0123456789"
	const clientPush = "client-frame-abcdef"

	srv, done := tmServe("ws", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("协议升级拿不到 Hijacker —— WebSocket 会直接 500")
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			t.Errorf("Hijack 失败: %v", err)
			return
		}
		defer conn.Close()

		brw.WriteString(respHead)
		brw.WriteString(serverPush)
		if err := brw.Flush(); err != nil {
			t.Errorf("劫持后写出失败: %v", err)
			return
		}
		buf := make([]byte, len(clientPush))
		if _, err := io.ReadFull(brw, buf); err != nil {
			t.Errorf("劫持后读取失败: %v", err)
			return
		}
		if string(buf) != clientPush {
			t.Errorf("劫持后读到的内容错乱: %q", string(buf))
		}
	})
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", addr)
	head := make([]byte, len(respHead)+len(serverPush))
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("读升级响应失败: %v", err)
	}
	if !strings.HasPrefix(string(head), "HTTP/1.1 101") {
		t.Fatalf("升级响应不对: %q", string(head))
	}
	if _, err := conn.Write([]byte(clientPush)); err != nil {
		t.Fatal(err)
	}
	<-done

	in, out := tmDrain("ws")
	wantOut := int64(len(respHead) + len(serverPush))
	if out != wantOut {
		t.Fatalf("劫持后出站计数 = %d，期望 %d", out, wantOut)
	}
	if in < int64(len(clientPush)) {
		t.Fatalf("劫持后入站计数 = %d，至少应有 %d（客户端推上来的帧）", in, len(clientPush))
	}
}
