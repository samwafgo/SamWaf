package wafhealth

import (
	"SamWaf/model"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func probeConfig() model.HealthyConfig {
	return model.HealthyConfig{CheckMethod: "GET", ResponseTime: 2, ExpectedCodes: "200,"}
}

func serverHost(t *testing.T, server *httptest.Server) model.Hosts {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return model.Hosts{Host: "site.example", Remote_host: u.Scheme + "://" + u.Hostname(), Remote_ip: u.Hostname(), Remote_port: port}
}

func TestHealthParseExpectedCodes(t *testing.T) {
	defaults := []int{200, 201, 202, 203, 204, 301, 302, 303, 307, 308}
	for _, tc := range []struct {
		input string
		want  []int
	}{
		{"", defaults}, {" , invalid, ", defaults}, {"200,", []int{200}},
		{" 200 , 204,invalid, 503,", []int{200, 204, 503}},
		{"99,600,-1", []int{99, 600, -1}},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := ParseExpectedCodes(tc.input); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHealthProbeRequestSemantics(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", ""} {
		for _, trans := range []int{0, 1} {
			t.Run(method+strconv.Itoa(trans), func(t *testing.T) {
				type request struct{ method, uri, host string }
				seen := make(chan request, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- request{r.Method, r.RequestURI, r.Host}
					w.WriteHeader(204)
				}))
				defer server.Close()
				host := serverHost(t, server)
				host.Remote_host = "http://url.example"
				host.Remote_port = 54321
				host.IsEnableLoadBalance = 1
				host.IsTransBackDomain = trans
				_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
				port, _ := strconv.Atoi(portText)
				config := probeConfig()
				config.CheckMethod, config.CheckPath, config.ExpectedCodes = method, "/health/a%20b?check=x%2Fy&n=2", "204"
				got := Probe(context.Background(), host, "127.0.0.1", port, config, "backend-1", false)
				if got.Outcome != Passed || got.StatusCode != 204 {
					t.Fatalf("probe: %+v", got)
				}
				if got.URL != "http://url.example:54321"+config.CheckPath || got.DialAddress != server.Listener.Addr().String() {
					t.Fatalf("URL/dial: %+v", got)
				}
				wantHost := "url.example:54321"
				if trans == 1 {
					wantHost = "http"
				}
				wantMethod := method
				if wantMethod == "" {
					wantMethod = "GET"
				}
				r := <-seen
				if r.method != wantMethod || r.uri != config.CheckPath || r.host != wantHost || got.RequestHost != wantHost || got.Method != wantMethod {
					t.Fatalf("request %+v, result %+v", r, got)
				}
				if got.BackendID != "backend-1" || got.BackIP != "127.0.0.1" || got.BackPort != port {
					t.Fatalf("metadata: %+v", got)
				}
			})
		}
	}
}

func TestHealthProbeSingleTargetAndWildcard(t *testing.T) {
	seen := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.RequestURI }))
	defer server.Close()
	host := serverHost(t, server)
	host.Remote_host = "http://url.example"
	got := Probe(context.Background(), host, "192.0.2.1", 1, probeConfig(), "single", false)
	if got.Outcome != Passed || got.DialAddress != server.Listener.Addr().String() {
		t.Fatalf("single target: %+v", got)
	}
	if uri := <-seen; uri != "/" {
		t.Fatalf("default path %q", uri)
	}
	host.Host, host.Remote_host = "*", "http://*"
	got = Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", false)
	if got.Outcome != Passed || got.URL != server.URL+"/" {
		t.Fatalf("wildcard: %+v", got)
	}
	<-seen
	host = serverHost(t, server)
	host.Remote_ip = ""
	got = Probe(context.Background(), host, "", host.Remote_port, probeConfig(), "single", false)
	if got.Outcome != Passed || got.DialAddress != server.Listener.Addr().String() {
		t.Fatalf("DNS fallback: %+v", got)
	}
	<-seen
}

func TestHealthProbeIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	host := model.Hosts{Host: "site.example", Remote_host: "http://[::1]", Remote_port: port, Remote_ip: "::1"}
	got := Probe(context.Background(), host, "::1", port, probeConfig(), "single", false)
	if got.Outcome != Passed || got.DialAddress != listener.Addr().String() || got.URL != server.URL+"/" {
		t.Fatalf("IPv6: %+v", got)
	}
	host.IsEnableLoadBalance = 1
	host.IsTransBackDomain = 1
	got = Probe(context.Background(), host, "::1", port, probeConfig(), "0", false)
	if got.Outcome != Passed || got.DialAddress != listener.Addr().String() || got.RequestHost != listener.Addr().String() {
		t.Fatalf("IPv6 LB: %+v", got)
	}
}

func TestHealthProbeTLS(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Host }))
	defer server.Close()
	host := serverHost(t, server)
	host.Remote_host = "https://url.example"
	host.IsTransBackDomain = 1
	got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", false)
	if got.Outcome != Passed || got.RequestHost != "https" {
		t.Fatalf("TLS: %+v", got)
	}
	if gotHost := <-seen; gotHost != "https" {
		t.Fatalf("TLS Host: %q", gotHost)
	}
}

func TestHealthProbeRedirectFixedDial(t *testing.T) {
	seen := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host + r.RequestURI
		if r.URL.Path == "/" {
			http.Redirect(w, r, "http://redirect.example:54322/final?x=1", http.StatusFound)
			return
		}
		w.WriteHeader(201)
	}))
	defer server.Close()
	host := serverHost(t, server)
	host.Remote_host = "http://initial.example"
	config := probeConfig()
	config.ExpectedCodes = "201"
	got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Passed || got.StatusCode != 201 {
		t.Fatalf("redirect: %+v", got)
	}
	if first := <-seen; first != "initial.example:"+strconv.Itoa(host.Remote_port)+"/" {
		t.Fatalf("first request %q", first)
	}
	if second := <-seen; second != "redirect.example:54322/final?x=1" {
		t.Fatalf("redirect request %q", second)
	}
	config.ExpectedCodes = "302"
	got = Probe(context.Background(), host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Failed || got.StatusCode != 201 || !strings.Contains(got.ErrorReason, "201") {
		t.Fatalf("final status: %+v", got)
	}
	<-seen
	<-seen
}

func TestHealthProbeSkippedAndFailures(t *testing.T) {
	for _, remote := range []string{"", "http://*.example", "http://bad%zz"} {
		got := Probe(context.Background(), model.Hosts{Remote_host: remote, Remote_port: 80}, "127.0.0.1", 80, probeConfig(), "single", false)
		if got.Outcome != Skipped || got.ErrorReason == "" || got.StatusCode != 0 {
			t.Fatalf("%q: %+v", remote, got)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host := serverHost(t, server)
	config := probeConfig()
	config.CheckMethod = "bad method"
	got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Failed || !strings.HasPrefix(got.ErrorReason, "创建请求失败:") {
		t.Fatalf("method: %+v", got)
	}
	server.Close()
	got = Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", false)
	if got.Outcome != Failed || !strings.HasPrefix(got.ErrorReason, "请求失败:") {
		t.Fatalf("connect: %+v", got)
	}
}

func TestHealthProbeTimeoutAndCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	host := serverHost(t, server)
	config := probeConfig()
	config.ResponseTime = 1
	start := time.Now()
	got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Failed || !strings.Contains(got.ErrorReason, "deadline exceeded") || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	defer cancel()
	start = time.Now()
	got = Probe(ctx, host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Failed || !strings.Contains(got.ErrorReason, "context canceled") || time.Since(start) > time.Second {
		t.Fatalf("cancel: %+v", got)
	}
	config.ResponseTime = 0
	got = Probe(context.Background(), host, host.Remote_ip, host.Remote_port, config, "single", false)
	if got.Outcome != Failed || !strings.Contains(got.ErrorReason, "deadline exceeded") {
		t.Fatalf("zero timeout: %+v", got)
	}
}

func TestHealthProbeBodyLimitAndHeaderTiming(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8192")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(80 * time.Millisecond)
		_, _ = w.Write([]byte(strings.Repeat("a", 4096)))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	host := serverHost(t, server)
	start := time.Now()
	got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", false)
	elapsed := time.Since(start).Milliseconds()
	if got.Outcome != Passed || elapsed > 1000 || elapsed-got.ElapsedMS < 50 {
		t.Fatalf("bounded body/header elapsed (%dms): %+v", elapsed, got)
	}
}

func TestHealthTransportPoolingAndCleanup(t *testing.T) {
	CleanupTransports(nil)
	defer CleanupTransports(nil)
	var connections atomic.Int32
	closed := make(chan struct{}, 10)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	host := serverHost(t, server)
	for i := 0; i < 2; i++ {
		if got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", true); got.Outcome != Passed {
			t.Fatalf("pooled: %+v", got)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("connections = %d", connections.Load())
	}
	addr := server.Listener.Addr().String()
	CleanupTransports(map[string]struct{}{addr: {}})
	transportMu.Lock()
	entry := transportPool[addr]
	transportMu.Unlock()
	if entry == nil {
		t.Fatal("valid transport removed")
	}
	CleanupTransports(nil)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pooled idle connection not closed")
	}
	for i := 0; i < 2; i++ {
		if got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "manual", false); got.Outcome != Passed {
			t.Fatalf("manual: %+v", got)
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("manual idle connection not closed")
		}
	}
	transportMu.Lock()
	count := len(transportPool)
	transportMu.Unlock()
	if count != 0 || connections.Load() != 3 {
		t.Fatalf("pool entries=%d, connections=%d", count, connections.Load())
	}
}

func TestHealthTransportCleanupDuringProbe(t *testing.T) {
	CleanupTransports(nil)
	defer CleanupTransports(nil)
	started, unblock, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-unblock
		_, _ = w.Write([]byte("ok"))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	host := serverHost(t, server)
	done := make(chan Result, 1)
	go func() {
		done <- Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", true)
	}()
	<-started
	CleanupTransports(nil)
	close(unblock)
	if got := <-done; got.Outcome != Passed {
		t.Fatalf("active probe: %+v", got)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("retired transport connection not closed")
	}
}

func TestHealthProbeDialGuard(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer server.Close()
	host := serverHost(t, server)
	host.Remote_ip = "localhost"
	addresses := make(chan string, 10)
	got := ProbeWithDialGuard(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "manual", func(address string) error {
		addresses <- address
		return errors.New("target not allowed")
	})
	if got.Outcome != Failed || !strings.Contains(got.ErrorReason, "target not allowed") || hits.Load() != 0 {
		t.Fatalf("rejected guard: %+v, hits=%d", got, hits.Load())
	}
	close(addresses)
	count := 0
	for address := range addresses {
		count++
		ip, port, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(ip) == nil || port != strconv.Itoa(host.Remote_port) {
			t.Fatalf("guard address must be resolved: %q", address)
		}
	}
	if count == 0 {
		t.Fatal("guard not called")
	}
	got = ProbeWithDialGuard(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "manual", func(address string) error {
		ip, _, err := net.SplitHostPort(address)
		if err != nil || net.ParseIP(ip) == nil {
			return errors.New("address not resolved")
		}
		return nil
	})
	if got.Outcome != Passed || hits.Load() != 1 {
		t.Fatalf("allowed guard: %+v, hits=%d", got, hits.Load())
	}
}

func TestHealthTransportConcurrentAccess(t *testing.T) {
	CleanupTransports(nil)
	defer CleanupTransports(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	host := serverHost(t, server)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := Probe(context.Background(), host, host.Remote_ip, host.Remote_port, probeConfig(), "single", true); got.Outcome != Passed {
				t.Errorf("concurrent probe: %+v", got)
			}
			CleanupTransports(nil)
		}()
	}
	wg.Wait()
}
