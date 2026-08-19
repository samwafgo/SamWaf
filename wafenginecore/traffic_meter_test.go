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
	"strings"
	"testing"
)

// ============ 测试脚手架 ============

// tmDrain 取出某站点这一轮记到的进出字节
func tmDrain(hostCode string) (in, out int64) {
	for _, s := range global.DrainTraffic() {
		if s.HostCode == hostCode {
			in += s.In
			out += s.Out
		}
	}
	return
}

// tmBaseRW 最小 ResponseWriter：只记录写了多少
type tmBaseRW struct {
	h    http.Header
	body bytes.Buffer
	code int
}

func (w *tmBaseRW) Header() http.Header { return w.h }
func (w *tmBaseRW) WriteHeader(c int)   { w.code = c }
func (w *tmBaseRW) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

// tmFullRW 带 ReaderFrom / Flusher / Pusher / CloseNotifier / Hijacker 的底层
type tmFullRW struct {
	tmBaseRW
	readFromCalled bool
	flushCalled    bool
	pushCalled     bool
	closeCh        chan bool
	hijackConn     net.Conn
	hijackBuffered string
}

func (w *tmFullRW) ReadFrom(r io.Reader) (int64, error) {
	w.readFromCalled = true
	return io.Copy(&w.body, r)
}
func (w *tmFullRW) Flush()                   { w.flushCalled = true }
func (w *tmFullRW) CloseNotify() <-chan bool { return w.closeCh }
func (w *tmFullRW) Push(string, *http.PushOptions) error {
	w.pushCalled = true
	return nil
}
func (w *tmFullRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijackConn == nil {
		return nil, nil, fmt.Errorf("no conn")
	}
	br := bufio.NewReader(io.MultiReader(strings.NewReader(w.hijackBuffered), w.hijackConn))
	if w.hijackBuffered != "" {
		_, _ = br.Peek(len(w.hijackBuffered)) // 让缓冲里真的有数据
	}
	return w.hijackConn, bufio.NewReadWriter(br, bufio.NewWriter(w.hijackConn)), nil
}

// ============ T10 包装层基本行为 ============

func TestCountingRW_CountsWrites(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")

	w.WriteHeader(200)
	for i := 0; i < 3; i++ {
		if _, err := w.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	settle()

	in, out := tmDrain("h1")
	if out != 3000 {
		t.Fatalf("出站计数 = %d，期望 3000", out)
	}
	if in != 0 {
		t.Fatalf("GET 无请求体，入站应为 0，实际 %d", in)
	}
	if base.body.Len() != 3000 {
		t.Fatalf("底层实际写入 %d 字节，包装层不该改变写出内容", base.body.Len())
	}
}

func TestCountingRW_InterfacePassthrough(t *testing.T) {
	global.DrainTraffic()
	base := &tmFullRW{tmBaseRW: tmBaseRW{h: http.Header{}}, closeCh: make(chan bool, 1)}
	w, _ := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")

	// Flusher：SSE / 流式响应靠它，不透传会被缓冲住
	f, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("包装层必须实现 http.Flusher")
	}
	f.Flush()
	if !base.flushCalled {
		t.Fatal("Flush 没有透传到底层")
	}

	// Pusher
	p, ok := w.(http.Pusher)
	if !ok {
		t.Fatal("包装层必须实现 http.Pusher")
	}
	if err := p.Push("/x", nil); err != nil {
		t.Fatal(err)
	}
	if !base.pushCalled {
		t.Fatal("Push 没有透传到底层")
	}

	// CloseNotifier：wafproxy/reverseproxy.go 会做类型断言
	cn, ok := w.(http.CloseNotifier)
	if !ok {
		t.Fatal("包装层必须实现 http.CloseNotifier")
	}
	if cn.CloseNotify() == nil {
		t.Fatal("CloseNotify 返回了 nil 通道")
	}

	// Unwrap：http.ResponseController 靠它找底层能力
	u, ok := w.(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("包装层必须提供 Unwrap")
	}
	if u.Unwrap() != http.ResponseWriter(base) {
		t.Fatal("Unwrap 没有返回底层 ResponseWriter")
	}
}

// 底层不支持 Hijack 时必须回 ErrNotSupported，而不是 panic 或假装成功
func TestCountingRW_HijackUnsupported(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	w, _ := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("包装层必须实现 http.Hijacker（否则 WebSocket 直接 500）")
	}
	if _, _, err := hj.Hijack(); err != http.ErrNotSupported {
		t.Fatalf("底层不支持时应返回 http.ErrNotSupported，实际 %v", err)
	}
}

// ============ T11 ReadFrom 必须委托给底层（保住 sendfile 快路径） ============

func TestCountingRW_ReadFromDelegates(t *testing.T) {
	global.DrainTraffic()
	base := &tmFullRW{tmBaseRW: tmBaseRW{h: http.Header{}}}
	w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")

	rf, ok := w.(io.ReaderFrom)
	if !ok {
		t.Fatal("包装层必须实现 io.ReaderFrom")
	}
	src := bytes.NewReader(make([]byte, 12345))
	n, err := rf.ReadFrom(src)
	if err != nil {
		t.Fatal(err)
	}
	settle()

	if !base.readFromCalled {
		t.Fatal("ReadFrom 没有委托给底层：sendfile/TransmitFile 快路径丢了")
	}
	if n != 12345 {
		t.Fatalf("ReadFrom 返回 %d，期望 12345", n)
	}
	if _, out := tmDrain("h1"); out != 12345 {
		t.Fatalf("出站计数 = %d，期望 12345", out)
	}
}

// 底层没有 ReaderFrom 时要退回逐块拷贝，且计数依然准确
func TestCountingRW_ReadFromFallback(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")

	n, err := w.(io.ReaderFrom).ReadFrom(bytes.NewReader(make([]byte, 999)))
	if err != nil || n != 999 {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	settle()
	if _, out := tmDrain("h1"); out != 999 {
		t.Fatalf("退回路径出站计数 = %d，期望 999", out)
	}
	if base.body.Len() != 999 {
		t.Fatalf("底层实际收到 %d 字节", base.body.Len())
	}
}

// ============ T13 结账语义 ============

// 重复结账不能重复计数（劫持连接可能有迟到字节）
func TestTrafficMeter_SettleIsIdempotent(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")
	w.Write(make([]byte, 100))
	settle()
	settle()
	settle()
	if _, out := tmDrain("h1"); out != 100 {
		t.Fatalf("重复结账造成重复计数：out = %d，期望 100", out)
	}
}

// handler panic 时，defer 结账仍然要把已发生的字节记上
func TestTrafficMeter_SettleAfterPanic(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	func() {
		defer func() { recover() }()
		w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "h1", "a.com")
		defer settle()
		w.Write(make([]byte, 512))
		panic("boom")
	}()
	if _, out := tmDrain("h1"); out != 512 {
		t.Fatalf("panic 后应仍结账 512 字节，实际 %d", out)
	}
}

// 没有解析到站点（host_code 为空）的流量无处归属，直接丢弃不建桶
func TestTrafficMeter_NoHostCodeDropped(t *testing.T) {
	global.DrainTraffic()
	base := &tmBaseRW{h: http.Header{}}
	w, settle := attachTrafficMeter(base, httptest.NewRequest("GET", "/", nil), "", "")
	w.Write(make([]byte, 4096))
	settle()
	if n := global.PendingTrafficBuckets(); n != 0 {
		t.Fatalf("无 host_code 不应建桶，实际 %d 个", n)
	}
}
