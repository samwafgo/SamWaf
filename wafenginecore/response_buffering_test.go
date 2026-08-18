package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafproxy"
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 端到端用例：真实后端 → 真实 wafproxy(挂 modifyResponse) → 真实 HTTP 客户端。
//
// 覆盖两件事：
//  1. 默认(响应缓冲开启)下 SSE 必须完整送达 —— issue #949 / #954 的验收线
//  2. 站点开关 IsEnableResponseBuffering 的行为 —— PR #953 引入，对标 nginx proxy_buffering

const (
	bufferingOn  = 1 // 开启响应缓冲(默认)
	bufferingOff = 0 // 关闭响应缓冲，等价 nginx proxy_buffering off
)

// newBufferingTestEngine 造一台最小可用的引擎：登记站点 + 全局站点，关闭出站敏感词
func newBufferingTestEngine(hostCode, hostKey string, buffering int) *WafEngine {
	waf := &WafEngine{}
	waf.InitRouting()
	waf.SensitiveDirectionMap = map[string]bool{}
	nt := waf.rt()
	nt.HostCode[hostCode] = hostKey
	nt.HostCode[global.GWAF_GLOBAL_HOST_CODE] = global.GWAF_GLOBAL_HOST_NAME
	nt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{}
	nt.HostTarget[hostKey] = &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code:                      hostCode,
			DefaultEncoding:           "auto",
			IsEnableResponseBuffering: buffering,
		},
	}
	return waf
}

// startWafFront 起一个前置服务：请求带上 waf_context 后交给反代
func startWafFront(t *testing.T, waf *WafEngine, hostCode string, target *url.URL, buffering int) *httptest.Server {
	t.Helper()
	proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(target, map[string]string{}, map[string]string{})
	proxy.ModifyResponse = waf.modifyResponse()
	if buffering == bufferingOff {
		proxy.FlushInterval = -1 // 与 applyResponseBuffering 保持一致
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		weblog := &innerbean.WebLog{
			URL:           r.URL.Path,
			HOST_CODE:     hostCode,
			UNIX_ADD_TIME: time.Now().UnixNano() / 1e6,
		}
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			HostCode: hostCode,
			Weblog:   weblog,
		})
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(front.Close)
	return front
}

// startSSEBackend 模拟 new-api / OpenAI Responses API：若干小 delta + 一条大 response.completed
func startSSEBackend(t *testing.T, deltaCount, completedSize int) (*httptest.Server, string) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("event: response.created\ndata: {\"type\":\"response.created\"}\n\n")
	for i := 0; i < deltaCount; i++ {
		fmt.Fprintf(&sb, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"块%d\"}\n\n", i)
	}
	fmt.Fprintf(&sb, "event: response.completed\ndata: {\"type\":\"response.completed\",\"text\":\"%s\"}\n\n",
		strings.Repeat("x", completedSize))
	body := sb.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for _, ev := range strings.SplitAfter(body, "\n\n") {
			if ev == "" {
				continue
			}
			io.WriteString(w, ev)
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, body
}

// #949/#954 主回归：默认配置(缓冲开启)下，长回答的 SSE 必须一个字节不少地送到客户端
func TestSSENotTruncatedWithBufferingEnabled(t *testing.T) {
	const hostCode, hostKey = "codexhost", "codex.example.com:443"
	backend, want := startSSEBackend(t, 5, 100000) // 100KB 的 response.completed
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine(hostCode, hostKey, bufferingOn)
	front := startWafFront(t, waf, hostCode, target, bufferingOn)

	resp, err := http.Get(front.URL + "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if string(got) != want {
		t.Errorf("SSE 被截断：后端发出 %d 字节，客户端收到 %d 字节（差 %d）",
			len(want), len(got), len(want)-len(got))
	}
	if !strings.Contains(string(got), "response.completed") {
		t.Error("客户端没收到 response.completed —— 对应 Codex 报 stream closed before response.completed")
	}
}

// 开关关闭时同样不能丢数据（此时走的是直通，不经过 StreamProcessor）
func TestSSENotTruncatedWithBufferingDisabled(t *testing.T) {
	const hostCode, hostKey = "codexhost2", "codex2.example.com:443"
	backend, want := startSSEBackend(t, 5, 100000)
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine(hostCode, hostKey, bufferingOff)
	front := startWafFront(t, waf, hostCode, target, bufferingOff)

	resp, err := http.Get(front.URL + "/v1/responses")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)

	if string(got) != want {
		t.Errorf("关闭缓冲后 SSE 仍被改动：后端 %d 字节，客户端 %d 字节", len(want), len(got))
	}
}

// startNDJSONBackend 模拟识别不出来的流式接口(Ollama 等)：application/x-ndjson，逐块下发
func startNDJSONBackend(t *testing.T, chunks int, gap time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "{\"delta\":\"第%d块\"}\n", i)
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(gap)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// firstChunkLatency 返回"首块内容到达客户端"的耗时
func firstChunkLatency(t *testing.T, frontURL string) time.Duration {
	t.Helper()
	start := time.Now()
	resp, err := http.Get(frontURL + "/api/chat")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	io.Copy(io.Discard, br)
	return elapsed
}

// 缓冲开启(默认)：非 SSE 的流式响应会被整包缓冲，首块要等到后端全部结束
func TestNonSSEStreamIsBufferedWhenEnabled(t *testing.T) {
	const hostCode, hostKey = "ndjson1", "ndjson1.example.com:443"
	backend := startNDJSONBackend(t, 5, 200*time.Millisecond) // 全程约 1s
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine(hostCode, hostKey, bufferingOn)
	front := startWafFront(t, waf, hostCode, target, bufferingOn)

	got := firstChunkLatency(t, front.URL)
	t.Logf("缓冲开启：首块 %v 到达", got.Round(time.Millisecond))
	if got < 800*time.Millisecond {
		t.Errorf("预期被整包缓冲(首块应≈1s后到)，实际 %v 就到了", got.Round(time.Millisecond))
	}
}

// 缓冲关闭：首块必须立刻到，这正是 issue #949 里 proxy_buffering off 的诉求
func TestNonSSEStreamFlushesWhenDisabled(t *testing.T) {
	const hostCode, hostKey = "ndjson2", "ndjson2.example.com:443"
	backend := startNDJSONBackend(t, 5, 200*time.Millisecond)
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine(hostCode, hostKey, bufferingOff)
	front := startWafFront(t, waf, hostCode, target, bufferingOff)

	got := firstChunkLatency(t, front.URL)
	t.Logf("缓冲关闭：首块 %v 到达", got.Round(time.Millisecond))
	if got > 300*time.Millisecond {
		t.Errorf("关闭缓冲后首块仍要等 %v，未生效", got.Round(time.Millisecond))
	}
}

// 关闭缓冲不得把 ACME 证书校验兜底一起短路掉。
// 这条兜底对应线上工单：后端(certbot 目录 / Apache ErrorDocument)对挑战路径抢答时，
// 必须用本地挑战文件应答，否则表现为"证书签不下来且日志里什么都没有"。
func TestACMEChallengeNotBypassedWhenBufferingDisabled(t *testing.T) {
	const hostCode, hostKey = "acmehost", "acme.example.com:443"
	setupChallenge(t, hostCode)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 后端对挑战路径抢答 404，模拟真实工单场景
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "<html>backend 404</html>")
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine(hostCode, hostKey, bufferingOff)
	front := startWafFront(t, waf, hostCode, target, bufferingOff)

	resp, err := http.Get(front.URL + global.GSSL_HTTP_CHANGLE_PATH + testChallengeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ACME 挑战被开关短路：状态码 %d，期望 200", resp.StatusCode)
	}
	if string(body) != testKeyAuth {
		t.Errorf("ACME 挑战没有用本地校验文件应答\ngot : %q\nwant: %q", string(body), testKeyAuth)
	}
}
