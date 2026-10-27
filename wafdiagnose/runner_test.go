package wafdiagnose

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/utils"
)

// 进程内单例代理服务器，见 TestPublicAllowProxyFollowsSystemProxy 注释。
var (
	proxyOnce   sync.Once
	proxyServer struct {
		srv  *httptest.Server
		hits *atomic.Int32
	}
)

func TestPublicAllowProxyFollowsSystemProxy(t *testing.T) {
	// http.ProxyFromEnvironment 用进程级 sync.Once 缓存首次读取的环境变量，
	// -count>1 或别的用例先触发缓存都会让本用例失真。因此代理服务器进程内
	// 单例（端口跨轮稳定，缓存指向始终有效），断言用命中数增量而非绝对值。
	proxyOnce.Do(func() {
		proxyServer.hits = new(atomic.Int32)
		proxyServer.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyServer.hits.Add(1)
			io.WriteString(w, "proxied")
		}))
	})
	t.Setenv("HTTP_PROXY", proxyServer.srv.URL)
	t.Setenv("HTTPS_PROXY", proxyServer.srv.URL)
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	old := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = ""
	defer func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = old }()

	before := proxyServer.hits.Load()
	r := Run(context.Background(), Target{URL: "http://proxy-target.invalid/", Method: "GET", Public: true, AllowProxy: true})
	if r.Status != "success" || r.StatusCode != 200 || proxyServer.hits.Load() != before+1 {
		t.Fatalf("allow-proxy result: %+v hits %d->%d", r, before, proxyServer.hits.Load())
	}

	before = proxyServer.hits.Load()
	direct := Run(context.Background(), Target{URL: "http://proxy-target.invalid/", Method: "GET", Public: true})
	if direct.Status == "success" || proxyServer.hits.Load() != before {
		t.Fatalf("direct probe must not use system proxy: %+v hits %d->%d", direct, before, proxyServer.hits.Load())
	}
}

func TestNonPublicTargetNeverUsesSystemProxy(t *testing.T) {
	// 本机入口/源站阶段结构上不走代理：即便 AllowProxy 被误置，
	// 非 public 目标也必须直连 FixedAddress，不读环境代理。
	proxyOnce.Do(func() {
		proxyServer.hits = new(atomic.Int32)
		proxyServer.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyServer.hits.Add(1)
			io.WriteString(w, "proxied")
		}))
	})
	t.Setenv("HTTP_PROXY", proxyServer.srv.URL)
	t.Setenv("HTTPS_PROXY", proxyServer.srv.URL)
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	u, _ := url.Parse(origin.URL)

	before := proxyServer.hits.Load()
	r := Run(context.Background(), Target{URL: "http://logical.invalid/x", Method: "GET", FixedAddress: u.Host, AllowProxy: true})
	if r.Status != "success" || proxyServer.hits.Load() != before || r.ActualAddress != u.Host {
		t.Fatalf("non-public target used system proxy: %+v hits %d->%d", r, before, proxyServer.hits.Load())
	}
}

func TestFixedAddressHostAndHEAD(t *testing.T) {
	var method, host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, host = r.Method, r.Host
		w.Header().Set("X-Test", "received")
		io.WriteString(w, "hello")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := Run(context.Background(), Target{URL: "http://logical.invalid:" + u.Port() + "/a?token=private-query", Method: "HEAD", Host: "virtual.example", FixedAddress: u.Host})
	if r.Status != "success" || !r.HTTPWritten || r.ActualAddress != u.Host || method != "HEAD" || host != "virtual.example" {
		t.Fatalf("unexpected diagnostic: %+v method=%s host=%s", r, method, host)
	}
	if r.ResponseBody != "" || !strings.Contains(r.Request, "HEAD /a?") || strings.Contains(r.Request, "private-query") {
		t.Fatalf("unexpected normalized messages: %+v", r)
	}
}

func TestTLSFailureAndSavedSkip(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "http-host.example" || r.TLS.ServerName != "virtual.example" {
			t.Errorf("Host=%s SNI=%s", r.Host, r.TLS.ServerName)
		}
		requests.Add(1)
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	target := Target{URL: "https://virtual.example:443", Host: "http-host.example", FixedAddress: u.Host}
	r := Run(context.Background(), target)
	if r.Stage != "tls" || r.Status != "error" || r.HTTPWritten || r.Request != "" || r.Response != "" || requests.Load() != 0 || r.ActualAddress != u.Host {
		t.Fatalf("TLS failure report: %+v", r)
	}
	if r.TLS == nil || r.TLS.Verified || r.TLS.Verification != "failed" || len(r.TLS.Certificates) == 0 {
		t.Fatalf("missing certificate metadata: %+v", r.TLS)
	}
	target.InsecureSkipVerify = true
	r = Run(context.Background(), target)
	if r.Status != "success" || !r.HTTPWritten || r.TLS == nil || r.TLS.Verified || r.TLS.Verification != "skipped" || r.SNI != "virtual.example" {
		t.Fatalf("saved skip report: %+v", r)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "/destination", http.StatusFound)
	}))
	defer srv.Close()
	r := Run(context.Background(), Target{URL: srv.URL})
	if r.Status != "success" || r.StatusCode != 302 || calls.Load() != 1 || !strings.Contains(r.Response, "302") {
		t.Fatalf("redirect report: %+v calls=%d", r, calls.Load())
	}
}

func TestBodyAndHeaderLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("z", MaxBodyBytes+10000))
	}))
	defer srv.Close()
	r := Run(context.Background(), Target{URL: srv.URL})
	if r.Status != "success" || !r.BodyTruncated || len(r.ResponseBody) != MaxBodyBytes {
		t.Fatalf("body limit result: status=%s length=%d truncated=%v", r.Status, len(r.ResponseBody), r.BodyTruncated)
	}
	headers := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("h", MaxHeaderBytes+1))
		io.WriteString(w, "ignored")
	}))
	defer headers.Close()
	r = Run(context.Background(), Target{URL: headers.URL})
	if r.Status != "error" || r.Response != "" || !r.HTTPWritten {
		t.Fatalf("header limit result: %+v", r)
	}
}

func TestCancellationAndGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := Run(ctx, Target{URL: srv.URL})
	if r.Status != "error" || r.Timings.TotalMS > 1000 {
		t.Fatalf("cancel result: %+v", r)
	}
	var seen string
	r = Run(context.Background(), Target{URL: srv.URL, DialGuard: func(address string) error { seen = address; return errors.New("controlled guard denied") }})
	host, _, err := net.SplitHostPort(seen)
	if err != nil || net.ParseIP(host) == nil || r.HTTPWritten || r.Status != "error" || !strings.Contains(r.Reason, "controlled guard denied") {
		t.Fatalf("guard result: %+v seen=%s", r, seen)
	}
}

func TestRedactionAcrossResult(t *testing.T) {
	const custom = "custom-private-value"
	const token = "auth-private-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=cookie-private-value")
		w.Header().Set("X-Echo", r.Header.Get("X-Custom"))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"password":"json-private-value","nested":[{"api_key":"json-key-value"}],"echo":"`+custom+`","query":"query-private-value","authorization":"`+token+`"}`)
	}))
	defer srv.Close()
	r := Run(context.Background(), Target{URL: srv.URL + "/?q=query-private-value", Headers: http.Header{"X-Custom": {custom}, "Authorization": {"Bearer " + token}}})
	b, _ := json.Marshal(r)
	for _, secret := range []string{custom, token, "json-private-value", "json-key-value", "query-private-value", "cookie-private-value"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("result contains %s: %s", secret, b)
		}
	}
	if !strings.Contains(r.ResponseBody, "redacted") || !r.HTTPWritten {
		t.Fatalf("unexpected redaction report: %+v", r)
	}
}

func TestRedactionExpansionBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat(strings.Repeat("a", 32), 4096))
	}))
	defer srv.Close()
	r := Run(context.Background(), Target{URL: srv.URL, Headers: http.Header{"X-Short": {"a"}, "Authorization": {"Bearer a"}}})
	if len(r.ResponseBody) > MaxBodyBytes || !strings.Contains(r.ResponseBody, strings.Repeat("a", 32)) {
		t.Fatalf("unexpected expansion budget: %d", len(r.ResponseBody))
	}
}

func TestFixedFallbackAndNumericGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var seen []string
	r := Run(context.Background(), Target{URL: "http://localhost:" + u.Port(), FixedAddress: net.JoinHostPort("127.0.0.2", u.Port()), Fallback: true, DialGuard: func(address string) error {
		seen = append(seen, address)
		host, _, _ := net.SplitHostPort(address)
		if net.ParseIP(host) == nil {
			t.Errorf("non-numeric guard input %s", address)
		}
		if host == "127.0.0.2" {
			return errors.New("controlled first attempt failure")
		}
		return nil
	}})
	if r.Status != "success" || len(seen) < 2 {
		t.Fatalf("fallback result: %+v seen=%v", r, seen)
	}
}

func TestPublicDirectTransportHasNoProxyExemption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("private target must not receive request") }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", srv.URL)
	t.Setenv("HTTPS_PROXY", srv.URL)
	old := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = ""
	defer func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = old }()
	transport := utils.SafeOutboundDirectTransport(nil)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("direct transport has proxy")
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("direct transport allowed private proxy endpoint as target")
	}
}

func TestPublicTLSAlwaysStrict(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("strict public TLS request reached HTTP") }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	old := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = u.Hostname()
	defer func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = old }()
	r := Run(context.Background(), Target{URL: srv.URL, Public: true, InsecureSkipVerify: true})
	if r.Status != "error" || r.Stage != "tls" || r.HTTPWritten || r.TLS == nil || r.TLS.Verification != "failed" {
		t.Fatalf("public TLS report: %+v", r)
	}
}
