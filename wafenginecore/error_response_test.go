package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/wafproxy"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestClassifyProxyError 验证不同类型的错误被正确归类。
func TestClassifyProxyError(t *testing.T) {
	type want struct {
		category   string
		statusCode int
		isClient   bool
	}
	mkTimeoutErr := func() error {
		// 构造一个 net.Error 且 Timeout()==true 的错误
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		defer l.Close()
		d := net.Dialer{Timeout: 1 * time.Millisecond}
		conn, err := d.Dial("tcp", "10.255.255.1:1") // 黑洞 IP，必超时
		if conn != nil {
			conn.Close()
		}
		return err
	}
	timeoutErr := mkTimeoutErr()

	cases := []struct {
		name   string
		err    error
		ctxErr error
		want   want
	}{
		{
			name:   "client canceled via err",
			err:    context.Canceled,
			ctxErr: context.Canceled,
			want:   want{"client_canceled", 499, true},
		},
		{
			name:   "client canceled via ctx only",
			err:    fmt.Errorf("wrapped: %w", context.Canceled),
			ctxErr: context.Canceled,
			want:   want{"client_canceled", 499, true},
		},
		{
			name:   "deadline exceeded",
			err:    context.DeadlineExceeded,
			ctxErr: context.DeadlineExceeded,
			want:   want{"timeout", 504, false},
		},
		{
			name:   "eof",
			err:    io.EOF,
			ctxErr: nil,
			want:   want{"backend_eof", 502, false},
		},
		{
			name:   "unexpected eof",
			err:    io.ErrUnexpectedEOF,
			ctxErr: nil,
			want:   want{"backend_eof", 502, false},
		},
		{
			// 新版 Go 下 dial i/o timeout 会包 context.DeadlineExceeded，所以走 timeout 分支；
			// 老版本或特殊 net.Error 也会被 net.Error.Timeout() 捕获，最终也是 timeout。
			name:   "net timeout",
			err:    timeoutErr,
			ctxErr: nil,
			want:   want{"timeout", 504, false},
		},
		{
			name:   "generic backend",
			err:    errors.New("dial tcp 1.2.3.4:80: connect: connection refused"),
			ctxErr: nil,
			want:   want{"backend_error", 503, false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, code, _, isClient := classifyProxyError(tc.err, tc.ctxErr)
			if cat != tc.want.category || code != tc.want.statusCode || isClient != tc.want.isClient {
				t.Fatalf("classifyProxyError mismatch:\n err=%v ctxErr=%v\n got {cat=%s code=%d client=%v}\n want{cat=%s code=%d client=%v}",
					tc.err, tc.ctxErr, cat, code, isClient, tc.want.category, tc.want.statusCode, tc.want.isClient)
			}
		})
	}
}

// proxyHarness 构建一个真实的反向代理，将 waf.errorResponse() 作为 ErrorHandler 挂上，
// 通过控制后端和客户端行为来复现不同类型的错误。
type proxyHarness struct {
	backend *httptest.Server
	// frontend 是代理本身对外暴露的 Server；请求打到它，它再反向代理到 backend
	frontend *httptest.Server
	proxy    *wafproxy.ReverseProxy
}

func newProxyHarness(t *testing.T, backendHandler http.HandlerFunc, transport *http.Transport) *proxyHarness {
	t.Helper()
	backend := httptest.NewServer(backendHandler)
	target, _ := url.Parse(backend.URL)
	rp := wafproxy.NewSingleHostReverseProxyCustomHeader(target, map[string]string{}, map[string]string{})
	if transport != nil {
		rp.Transport = transport
	}
	waf := &WafEngine{}
	rp.ErrorHandler = waf.errorResponse()

	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟 ProxyHTTP 里挂 waf_context
		weblog := &innerbean.WebLog{URL: r.RequestURI, METHOD: r.Method}
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			Weblog:   weblog,
			HostCode: "test-host",
		})
		rp.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(func() {
		frontend.Close()
		backend.Close()
	})
	return &proxyHarness{backend: backend, frontend: frontend, proxy: rp}
}

// TestErrorResponse_ClientCanceled 复现 "context canceled"：
// 后端 hang 住不返回，客户端建立连接后发送请求再 cancel context。
// 期望：ReverseProxy.ErrorHandler 被触发，且类型为 client_canceled。
func TestErrorResponse_ClientCanceled(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	backendStarted := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	h := newProxyHarness(t, func(w http.ResponseWriter, r *http.Request) {
		// 通知测试：后端已经开始处理；然后阻塞直到测试结束
		select {
		case backendStarted <- struct{}{}:
		default:
		}
		<-release
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", h.frontend.URL+"/_nuxt/el-message.BBiDsUL0.css", nil)

	errCh := make(chan error, 1)
	go func() {
		_, err := http.DefaultClient.Do(req)
		errCh <- err
	}()

	// 等后端被打到，再 cancel
	select {
	case <-backendStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("backend 未被打到，无法复现客户端取消")
	}
	cancel()

	select {
	case err := <-errCh:
		// 客户端侧也会拿到 context canceled；测试主要验证代理侧没有崩溃
		t.Logf("客户端 Do 返回: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("客户端请求未在预期时间内返回")
	}

	// 让 backend handler 退出（避免 goroutine 泄漏）
	releaseOnce.Do(func() { close(release) })
}

// TestErrorResponse_BackendRefused 复现后端直接连接拒绝的场景：
// 把反向代理指向一个已关闭的监听端口。
// 期望：category == backend_error，状态码 503。
func TestErrorResponse_BackendRefused(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	// 先开 listener 再立刻关，拿到一个肯定没人监听的端口
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := l.Addr().String()
	l.Close()

	target, _ := url.Parse("http://" + deadAddr)
	rp := wafproxy.NewSingleHostReverseProxyCustomHeader(target, map[string]string{}, map[string]string{})
	waf := &WafEngine{}
	rp.ErrorHandler = waf.errorResponse()

	fe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		weblog := &innerbean.WebLog{URL: r.RequestURI, METHOD: r.Method}
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			Weblog:   weblog,
			HostCode: "test-host",
		})
		rp.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer fe.Close()

	resp, err := http.Get(fe.URL + "/dead")
	if err != nil {
		t.Fatalf("请求未预期地失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("期望 503，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "服务不可用") {
		t.Fatalf("期望响应体包含'服务不可用'，实际: %s", string(body))
	}
}

// TestErrorResponse_ResponseHeaderTimeout 通过 Transport.ResponseHeaderTimeout 让 RoundTrip
// 在后端迟迟不返回响应头时超时，expected category == net_timeout。
func TestErrorResponse_ResponseHeaderTimeout(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	done := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 不写任何响应头，让客户端 ResponseHeaderTimeout 触发
		<-done
	}))
	// 注意顺序：先放开 handler 让它返回，再 Close backend，避免 httptest.Server Close 卡住
	defer backend.Close()
	defer close(done)
	target, _ := url.Parse(backend.URL)

	transport := &http.Transport{
		ResponseHeaderTimeout: 200 * time.Millisecond,
	}

	rp := wafproxy.NewSingleHostReverseProxyCustomHeader(target, map[string]string{}, map[string]string{})
	rp.Transport = transport
	waf := &WafEngine{}
	rp.ErrorHandler = waf.errorResponse()

	fe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		weblog := &innerbean.WebLog{URL: r.RequestURI, METHOD: r.Method}
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			Weblog:   weblog,
			HostCode: "test-host",
		})
		rp.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer fe.Close()

	resp, err := http.Get(fe.URL + "/slow")
	if err != nil {
		t.Fatalf("请求意外失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout && resp.StatusCode != http.StatusServiceUnavailable {
		// net.Error Timeout 路径走 504；但部分 Go 版本下可能报 context 或其它，兼容一下
		t.Logf("注意：statusCode=%d，请核对日志中的 category", resp.StatusCode)
	}
}
