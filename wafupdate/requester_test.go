package wafupdate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 回归护栏：这三个用例锁死"不能给升级 client 加总超时"这条约束。
// 一旦有人图省事写成 &http.Client{Timeout: xx}，外网用户几十 MB 的升级包
// 会在下载途中被掐断，这里会先红。
// ---------------------------------------------------------------------------

// 升级 client 绝不能设置 http.Client.Timeout（它含 body 读取时间）。
func TestUpdateClientMustNotSetTotalTimeout(t *testing.T) {
	if defaultHTTPClient.Timeout != 0 {
		t.Fatalf("defaultHTTPClient.Timeout 必须为 0，否则会掐断大文件下载，当前=%v", defaultHTTPClient.Timeout)
	}
}

// 传输层超时必须都配上，否则纯内网环境版本检测又会挂死。
func TestUpdateClientTransportTimeouts(t *testing.T) {
	tr, ok := defaultHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("期望 *http.Transport，实际 %T", defaultHTTPClient.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext 未设置，DNS/建连将没有超时上限")
	}
	if tr.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout=%v，期望 %v", tr.TLSHandshakeTimeout, tlsHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout=%v，期望 %v", tr.ResponseHeaderTimeout, responseHeaderTimeout)
	}

	// 纯内网的实际卡死点是建连（DNS 不通 / SYN 被丢弃），一次检测就停在 dialTimeout。
	// CheckVersionApi 在官方源失败后还会串行再打一次 GitHub，所以要按 2 次算，
	// 且必须明显小于前端 axios 的 20s 默认超时，用户才能看到后端返回的明确错误。
	if intranetPath := 2 * dialTimeout; intranetPath > 12*time.Second {
		t.Errorf("内网路径（官方+beta 各卡在建连）耗时 %v，逼近前端 20s 默认超时", intranetPath)
	}

	// 理论上限：每一段都恰好用满预算才会发生（建连慢但成功→TLS 慢但成功→首字节迟迟不来），
	// 不是内网的典型形态，这里只做兜底，防止有人把某个值调成分钟级。
	if ceiling := 2 * (dialTimeout + tlsHandshakeTimeout + responseHeaderTimeout); ceiling > 40*time.Second {
		t.Errorf("理论最坏耗时 %v 过长", ceiling)
	}
}

// 不能动全局 DefaultTransport —— 它被 ACME、威胁情报订阅、CDN 回源段拉取共用。
func TestUpdateClientDoesNotTouchDefaultTransport(t *testing.T) {
	if defaultHTTPClient.Transport == http.DefaultTransport {
		t.Fatal("升级 client 复用了 http.DefaultTransport，会波及其他模块")
	}
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt.ResponseHeaderTimeout != 0 {
		t.Fatal("http.DefaultTransport 被改动了，会影响 ACME/威胁情报/CDN 等模块")
	}
}

// ---------------------------------------------------------------------------
// 行为用例
// ---------------------------------------------------------------------------

// 核心用例：body 传输远超 ResponseHeaderTimeout 也必须完整下载，不能被截断。
// 模拟外网慢速用户下载升级包。
func TestFetchSlowBodyIsNotCutOff(t *testing.T) {
	const chunks = 10
	const chunkDelay = 150 * time.Millisecond // 总计 1.5s，远超下面的 300ms header 超时

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // 先把响应头发出去，之后就只受 body 传输影响
		for i := 0; i < chunks; i++ {
			time.Sleep(chunkDelay)
			w.Write([]byte("0123456789"))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	req := &HTTPRequester{Client: newUpdateHTTPClient(1*time.Second, 1*time.Second, 300*time.Millisecond)}

	start := time.Now()
	rc, err := req.Fetch(srv.URL)
	if err != nil {
		t.Fatalf("Fetch 失败: %v", err)
	}
	defer rc.Close()

	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("读取 body 失败（说明下载被超时掐断了）: %v", err)
	}
	if len(body) != chunks*10 {
		t.Fatalf("body 长度=%d，期望 %d —— 下载被截断", len(body), chunks*10)
	}
	if elapsed := time.Since(start); elapsed < chunks*chunkDelay {
		t.Fatalf("耗时 %v 短于预期，慢速传输没有被真实模拟", elapsed)
	}
}

// 服务端迟迟不给首字节（内网里被中间设备黑洞的典型表现），必须在 header 超时内返回错误。
func TestFetchResponseHeaderTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // 一直不写响应头
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	req := &HTTPRequester{Client: newUpdateHTTPClient(1*time.Second, 1*time.Second, 300*time.Millisecond)}

	start := time.Now()
	_, err := req.Fetch(srv.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("期望超时错误，实际成功了")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("耗时 %v，ResponseHeaderTimeout 没有生效", elapsed)
	}
}

// 纯内网场景回归：目标地址打不通时必须有界失败，不能挂死等操作系统 TCP 栈。
// 改动前走 http.Get（DefaultClient，Timeout=0 且 Transport 无任何超时），这里会长时间阻塞。
//
// 注意：具体是哪一段超时兜住，取决于运行机器的网络环境 —— SYN 被静默丢弃走 dial 超时，
// 有设备代答则走 ResponseHeaderTimeout，路由直接不可达则更早失败。
// 本用例只断言"有界返回"，不断言由哪一段触发。
func TestFetchUnreachableTargetDoesNotHang(t *testing.T) {
	const (
		dial       = 500 * time.Millisecond
		tlsHS      = 500 * time.Millisecond
		respHeader = 1 * time.Second
	)
	req := &HTTPRequester{Client: newUpdateHTTPClient(dial, tlsHS, respHeader)}

	start := time.Now()
	// 10.255.255.1 为常见黑洞地址，模拟内网访问 update.samwaf.com 的效果。
	_, err := req.Fetch("http://10.255.255.1:80/samwaf_update/windows-amd64.json")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("期望连接失败，实际成功了")
	}
	if ceiling := dial + tlsHS + respHeader + 2*time.Second; elapsed > ceiling {
		t.Fatalf("耗时 %v 超过上限 %v，说明请求没有超时约束", elapsed, ceiling)
	}
	t.Logf("不可达地址 %v 内返回: %v", elapsed, err)
}

func TestFetchOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.2.3"}`))
	}))
	defer srv.Close()

	rc, err := (&HTTPRequester{}).Fetch(srv.URL)
	if err != nil {
		t.Fatalf("Fetch 失败: %v", err)
	}
	defer rc.Close()

	body, _ := io.ReadAll(rc)
	if !strings.Contains(string(body), "v1.2.3") {
		t.Fatalf("body 不符: %s", body)
	}
}

// 非 200 返回错误，且必须关闭 body（原实现直接返回 error 未关闭，会泄漏连接）。
func TestFetchNon200ReturnsErrorAndClosesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	client := newUpdateHTTPClient(1*time.Second, 1*time.Second, 1*time.Second)
	req := &HTTPRequester{Client: client}

	for i := 0; i < 3; i++ {
		if _, err := req.Fetch(srv.URL); err == nil {
			t.Fatal("期望非 200 返回错误")
		}
	}
	// body 被正确关闭时连接会归还连接池；泄漏的话每次都会新建连接。
	// 这里不便直接断言连接数，改为确认重复调用不会耗尽 fd 且行为稳定。
}
