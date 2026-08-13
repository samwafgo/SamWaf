package wafenginecore

import (
	"SamWaf/common/queue"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/wafacme"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// 这组用例锁的是两个线上工单的成因：
//   - #IK7TAA：后端自带 certbot 目录，对挑战路径抢答 200，本地校验文件被状态码白名单挡掉
//   - Windows 例：后端 Apache 的 ErrorDocument 静态 404 页带 Accept-Ranges: bytes，
//     让整段兜底被 isStaticAssist 判成"静态资源"跳过，连日志都不打
//
// 以及新加的快速通道自身的防刷与安全边界。

const testChallengeToken = "q1IHnW37smIYQO7piKBIhI7GbxI9BKHPmPbH45_pai4"
const testKeyAuth = "q1IHnW37smIYQO7piKBIhI7GbxI9BKHPmPbH45_pai4.Zm9vYmFyYmF6cXV4"

// TestMain 补齐引擎在真实进程里由启动流程完成的初始化：
// 日志器、以及 weblog 入库队列（命中放行时会往里 Enqueue）。
func TestMain(m *testing.M) {
	global.GSSL_HTTP_CHANGLE_PATH = "/.well-known/acme-challenge/"
	zlog.InitZLog(false, "console")
	if global.GQEQUE_LOG_DB == nil {
		global.GQEQUE_LOG_DB = queue.NewQueue()
	}
	os.Exit(m.Run())
}

// setupChallenge 登记一个挑战（等价于 lego provider 的 Present），返回 hostCode。
func setupChallenge(t *testing.T, hostCode string) string {
	t.Helper()
	wafacme.Present(hostCode, testChallengeToken, testKeyAuth)
	t.Cleanup(func() { wafacme.CleanUp(hostCode, testChallengeToken) })
	return hostCode
}

func acmeRequest(method, token string) *http.Request {
	return httptest.NewRequest(method, "http://x.example.com/.well-known/acme-challenge/"+token, nil)
}

// ── 功能 ────────────────────────────────────────────────────────────

// TestFastPath_MemoryHit 快速通道命中内存注册表：直接应答，不需要磁盘、不回源。
func TestFastPath_MemoryHit(t *testing.T) {
	hostCode := setupChallenge(t, "host-fastpath")
	waf := &WafEngine{}
	w := httptest.NewRecorder()
	weblog := &innerbean.WebLog{HOST_CODE: hostCode, HOST: "http://x.example.com",
		URL: "/.well-known/acme-challenge/" + testChallengeToken}

	if !waf.tryServeACMEChallenge(w, acmeRequest("GET", testChallengeToken), weblog) {
		t.Fatal("本地已登记挑战，快速通道必须命中")
	}
	if got := w.Body.String(); got != testKeyAuth {
		t.Errorf("返回内容 = %q，期望 %q", got, testKeyAuth)
	}
	if w.Code != http.StatusOK {
		t.Errorf("状态码 = %d，期望 200", w.Code)
	}
}

// TestFastPath_MissFallsThrough 本地没有挑战文件时必须回落，绝不能自作主张放行。
//
// 这是整个改动里最重要的一条安全断言：一旦快速通道在未命中时也返回 true，
// /.well-known/acme-challenge/ 就成了绕过全部检测的万能前缀。
func TestFastPath_MissFallsThrough(t *testing.T) {
	waf := &WafEngine{}
	w := httptest.NewRecorder()
	weblog := &innerbean.WebLog{HOST_CODE: "host-no-challenge"}

	if waf.tryServeACMEChallenge(w, acmeRequest("GET", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"), weblog) {
		t.Fatal("本地无挑战文件时必须回落原链路（返回 false），否则该前缀就是绕过原语")
	}
	if w.Body.Len() != 0 {
		t.Error("未命中时不应向客户端写任何内容")
	}
}

// TestResponseFallback_BackendStatuses 响应侧兜底：本地有文件时，后端返回什么都不影响。
// 覆盖 #IK7TAA 的 200 抢答，以及后端 5xx。
func TestResponseFallback_BackendStatuses(t *testing.T) {
	hostCode := setupChallenge(t, "host-resp")

	for _, status := range []int{200, 404, 403, 502, 301} {
		resp := &http.Response{StatusCode: status, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader("后端自己的内容"))}
		weblog := &innerbean.WebLog{HOST_CODE: hostCode, HOST: "http://x.example.com",
			URL: "/.well-known/acme-challenge/" + testChallengeToken}

		if !handleACMEChallengeResponse(resp, weblog, 0) {
			t.Fatalf("后端%d：ACME 路径必须由该函数接管", status)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != testKeyAuth {
			t.Errorf("后端%d：响应体 = %q，期望被本地校验文件覆盖为 %q", status, string(body), testKeyAuth)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("后端%d：状态码 = %d，期望被改写为 200", status, resp.StatusCode)
		}
	}
}

// TestResponseFallback_StripsContentEncoding 后端带 gzip 头时，换掉正文后必须删掉编码头，
// 否则 CA 会拿 gzip 解码器去解一段明文，报的错跟证书毫无关系。
func TestResponseFallback_StripsContentEncoding(t *testing.T) {
	hostCode := setupChallenge(t, "host-gzip")
	resp := &http.Response{StatusCode: 404, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader("x"))}
	resp.Header.Set("Content-Encoding", "gzip")
	weblog := &innerbean.WebLog{HOST_CODE: hostCode, HOST: "http://x.example.com",
		URL: "/.well-known/acme-challenge/" + testChallengeToken}

	handleACMEChallengeResponse(resp, weblog, 0)
	if resp.Header.Get("Content-Encoding") != "" {
		t.Error("覆盖正文后必须删除 Content-Encoding")
	}
}

// TestResponseFallback_NonACMEUntouched 非 ACME 路径必须原样放过，交给常规响应处理。
func TestResponseFallback_NonACMEUntouched(t *testing.T) {
	resp := &http.Response{StatusCode: 404, Header: make(http.Header)}
	weblog := &innerbean.WebLog{HOST_CODE: "host-x", URL: "/admin/index.php"}
	if handleACMEChallengeResponse(resp, weblog, 0) {
		t.Error("非 ACME 路径不该被接管")
	}
}

// TestHostCodeIsolation A 站点登记的 token，B 站点的请求不能读到。
func TestHostCodeIsolation(t *testing.T) {
	setupChallenge(t, "host-A")
	waf := &WafEngine{}
	w := httptest.NewRecorder()
	weblog := &innerbean.WebLog{HOST_CODE: "host-B"}

	if waf.tryServeACMEChallenge(w, acmeRequest("GET", testChallengeToken), weblog) {
		t.Fatal("跨站点读到了别的站点的挑战 token")
	}
}

// TestFastPath_DiskFallback 内存表没有但磁盘上有（蓝绿升级双 Worker 并存的情形）。
func TestFastPath_DiskFallback(t *testing.T) {
	hostCode := "host-disk"

	// 造出 <当前目录>/data/vhost/<hostCode>/.well-known/acme-challenge/<token>
	dir := filepath.Join(acmeChallengeFilePath(hostCode, testChallengeToken), "..")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("无法创建测试目录，跳过：%v", err)
	}
	fp := acmeChallengeFilePath(hostCode, testChallengeToken)
	if err := os.WriteFile(fp, []byte(testKeyAuth), 0o644); err != nil {
		t.Skipf("无法写入测试文件，跳过：%v", err)
	}
	t.Cleanup(func() { os.Remove(fp) })

	// 只开门闩、不登记内存表，模拟"另一个 Worker"
	wafacme.Present(hostCode, "other-token-not-this-one", "x")
	t.Cleanup(func() { wafacme.CleanUp(hostCode, "other-token-not-this-one") })

	waf := &WafEngine{}
	w := httptest.NewRecorder()
	weblog := &innerbean.WebLog{HOST_CODE: hostCode, HOST: "http://x.example.com",
		URL: "/.well-known/acme-challenge/" + testChallengeToken}

	if !waf.tryServeACMEChallenge(w, acmeRequest("GET", testChallengeToken), weblog) {
		t.Fatal("内存表未命中时应回落读盘并命中")
	}
	if w.Body.String() != testKeyAuth {
		t.Errorf("磁盘兜底返回内容 = %q", w.Body.String())
	}
}

// ── 抗刷 ────────────────────────────────────────────────────────────

// TestGateClosed_NoDiskIO 没有进行中的挑战时，狂刷该路径必须一次磁盘 IO 都不产生。
//
// /.well-known/ 是互联网上被扫烂的路径，任何人都能构造随机 token 打进来。
// 这一条是防刷设计的核心：门闩关闭时连 os.Open 都不该被调用。
func TestGateClosed_NoDiskIO(t *testing.T) {
	// 门闩在 CleanUp 后还会留一段尾巴容忍 CA 重试，测试里等不起，直接复位
	wafacme.ResetForTest()

	var opens int32
	orig := challengeFileOpen
	challengeFileOpen = func(name string) (*os.File, error) {
		atomic.AddInt32(&opens, 1)
		return orig(name)
	}
	t.Cleanup(func() { challengeFileOpen = orig })

	waf := &WafEngine{}
	weblog := &innerbean.WebLog{HOST_CODE: "host-flood"}
	for i := 0; i < 1000; i++ {
		w := httptest.NewRecorder()
		// 每次都换一个 token，模拟扫描器穷举
		if waf.tryServeACMEChallenge(w, acmeRequest("GET", "tokenflood"+strings.Repeat("a", i%20)), weblog) {
			t.Fatal("门闩关闭时不该命中")
		}
	}
	if n := atomic.LoadInt32(&opens); n != 0 {
		t.Errorf("门闩关闭时狂刷 1000 次产生了 %d 次磁盘打开，期望 0", n)
	}
}

// TestGateOpen_MemoryHitNoDiskIO 门闩开着且内存表命中时，同样不该碰磁盘。
func TestGateOpen_MemoryHitNoDiskIO(t *testing.T) {
	wafacme.ResetForTest()
	hostCode := setupChallenge(t, "host-memonly")

	var opens int32
	orig := challengeFileOpen
	challengeFileOpen = func(name string) (*os.File, error) {
		atomic.AddInt32(&opens, 1)
		return orig(name)
	}
	t.Cleanup(func() { challengeFileOpen = orig })

	waf := &WafEngine{}
	weblog := &innerbean.WebLog{HOST_CODE: hostCode, HOST: "http://x.example.com",
		URL: "/.well-known/acme-challenge/" + testChallengeToken}
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		if !waf.tryServeACMEChallenge(w, acmeRequest("GET", testChallengeToken), weblog) {
			t.Fatal("内存表已登记，必须命中")
		}
	}
	if n := atomic.LoadInt32(&opens); n != 0 {
		t.Errorf("内存表命中时产生了 %d 次磁盘打开，期望 0", n)
	}
}

// TestDiskReadRateLimited 门闩开着但内存表未命中时，读盘要限速。
func TestDiskReadRateLimited(t *testing.T) {
	hostCode := "host-ratelimit"
	wafacme.Present(hostCode, "some-token", "x")
	t.Cleanup(func() { wafacme.CleanUp(hostCode, "some-token") })

	allowed := 0
	for i := 0; i < 500; i++ {
		if wafacme.AllowDiskRead() {
			allowed++
		}
	}
	if allowed >= 500 {
		t.Errorf("读盘限速未生效：500 次全部放行")
	}
	if allowed == 0 {
		t.Error("限速过严：一次都不放行会让蓝绿升级期间的校验必然失败")
	}
	t.Logf("500 次读盘请求放行 %d 次", allowed)
}

// ── 安全 ────────────────────────────────────────────────────────────

// TestFastPath_RejectsTraversalAndJunk 穿越与畸形 token 一律不得命中。
func TestFastPath_RejectsTraversalAndJunk(t *testing.T) {
	setupChallenge(t, "host-sec")
	waf := &WafEngine{}
	weblog := &innerbean.WebLog{HOST_CODE: "host-sec"}

	// 直接构造 URL 而不用 httptest.NewRequest：后者会对畸形 URL(如含空格) 直接 panic，
	// 而这里要测的恰恰是这类畸形输入
	bad := []string{
		"/.well-known/acme-challenge/../../admin",
		"/.well-known/acme-challenge/../../../etc/passwd",
		"/.well-known/acme-challenge/./../../etc/passwd",
		"/foo/../.well-known/acme-challenge/" + testChallengeToken,
		"/.well-known/acme-challenge/",
		"/.well-known/acme-challenge/to ken",
		"/.well-known/acme-challenge/" + strings.Repeat("a", 300),
		"/.well-known/other/" + testChallengeToken,
		"/admin",
	}
	for _, p := range bad {
		w := httptest.NewRecorder()
		r := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: p},
			Host:   "x.example.com",
			Header: make(http.Header),
		}
		if waf.tryServeACMEChallenge(w, r, weblog) {
			t.Errorf("畸形路径 %s 不该命中快速通道", p)
		}
	}

	// 编码形态：net/http 会把 %2e%2e 解码进 URL.Path，穿越判定看的就是解码后的值
	u, err := url.Parse("http://x.example.com/.well-known/acme-challenge/%2e%2e/%2e%2e/admin")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if waf.tryServeACMEChallenge(w, &http.Request{Method: "GET", URL: u, Host: u.Host, Header: make(http.Header)}, weblog) {
		t.Error("%2e%2e 编码的穿越不该命中快速通道")
	}
}

// TestFastPath_OnlyGetHead 只有 GET/HEAD 才可能是 CA 的校验请求。
func TestFastPath_OnlyGetHead(t *testing.T) {
	setupChallenge(t, "host-method")
	waf := &WafEngine{}
	weblog := &innerbean.WebLog{HOST_CODE: "host-method", HOST: "http://x.example.com",
		URL: "/.well-known/acme-challenge/" + testChallengeToken}

	for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		w := httptest.NewRecorder()
		if waf.tryServeACMEChallenge(w, acmeRequest(m, testChallengeToken), weblog) {
			t.Errorf("%s 不该命中快速通道", m)
		}
	}
	w := httptest.NewRecorder()
	if !waf.tryServeACMEChallenge(w, acmeRequest("HEAD", testChallengeToken), weblog) {
		t.Error("HEAD 应当命中（容错）")
	}
	if w.Body.Len() != 0 {
		t.Error("HEAD 不应返回响应体")
	}
}

// TestACMENotNestedInStaticAssist AST 护栏。
//
// 真实工单的成因就是 ACME 兜底被嵌套在 `if !isStaticAssist {` 内部：
// 后端回一个带 Accept-Ranges: bytes 的响应就会让整段（连同日志）被跳过，
// 表现为"签不出证书而且日志里什么都没有"。这条用例钉住它不许再被圈回去。
func TestACMENotNestedInStaticAssist(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "wafengine.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 wafengine.go 失败: %v", err)
	}

	// 找到所有以 isStaticAssist 为条件的 if，检查其函数体内不得出现 ACME 处理调用
	var offenders []string
	guarded := 0
	ast.Inspect(f, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Cond == nil {
			return true
		}
		if !strings.Contains(exprString(fset, ifStmt.Cond), "isStaticAssist") {
			return true
		}
		guarded++
		ast.Inspect(ifStmt.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := exprString(fset, call.Fun)
			if name == "handleACMEChallengeResponse" {
				offenders = append(offenders, fset.Position(call.Pos()).String())
			}
			return true
		})
		return true
	})

	// 自检：如果一个 isStaticAssist 判定都没找到，说明 AST 匹配写错了或代码结构变了，
	// 这条护栏就成了永远绿的空壳，比没有还糟
	if guarded == 0 {
		t.Fatal("没有在 wafengine.go 里找到任何 isStaticAssist 判定，护栏失效，请检查本用例的 AST 匹配")
	}
	if len(offenders) > 0 {
		t.Errorf("ACME 处理不得嵌套在 isStaticAssist 判定内部（否则后端带 Accept-Ranges 时整段被跳过），出现位置：%v", offenders)
	}
	t.Logf("已检查 %d 处 isStaticAssist 判定，均未包含 ACME 处理", guarded)
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			sb.WriteString(id.Name)
			sb.WriteString(".")
		}
		return true
	})
	return sb.String()
}
