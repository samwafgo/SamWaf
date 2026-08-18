package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/loadbalance"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 开启负载均衡的站点上

func newLBTestEngine(t *testing.T, hostCode, hostKey string, backendHost string, backendPort int) (*WafEngine, *wafenginmodel.HostSafe) {
	t.Helper()
	waf := &WafEngine{}
	waf.InitRouting()
	waf.SensitiveDirectionMap = map[string]bool{}
	waf.TransportPool = map[string]*http.Transport{}

	hs := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			Code:                      hostCode,
			DefaultEncoding:           "auto",
			IsEnableResponseBuffering: 1,
			IsEnableLoadBalance:       1,
			LoadBalanceStage:          1, // 加权轮询
		},
		LoadBalanceLists: []model.LoadBalance{
			{Remote_ip: backendHost, Remote_port: backendPort, Weight: 1},
		},
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{
			WeightRoundRobinBalance: loadbalance.NewWeightRoundRobinBalance(hostCode),
			IpHashBalance:           loadbalance.NewConsistentHashBalance(nil, hostCode),
		},
	}
	nt := waf.rt()
	nt.HostCode[hostCode] = hostKey
	nt.HostCode[global.GWAF_GLOBAL_HOST_CODE] = global.GWAF_GLOBAL_HOST_NAME
	nt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{}
	nt.HostTarget[hostKey] = hs
	return waf, hs
}

func TestLoadBalanceLockStallsWholeSiteDuringStream(t *testing.T) {
	// 后端：/stream 慢慢吐 SSE（2 秒），/fast 立即返回
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/fast") {
			io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < 10; i++ {
			fmt.Fprintf(w, "event: tick\ndata: {\"i\":%d}\n\n", i)
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}))
	defer backend.Close()

	bu, _ := url.Parse(backend.URL)
	port, _ := strconv.Atoi(bu.Port())

	const hostCode, hostKey = "lbhost", "lb.example.com:443"
	waf, hs := newLBTestEngine(t, hostCode, hostKey, bu.Hostname(), port)

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		weblog := &innerbean.WebLog{
			URL: r.URL.Path, HOST_CODE: hostCode,
			UNIX_ADD_TIME: time.Now().UnixNano() / 1e6,
		}
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			HostCode: hostCode, Weblog: weblog,
		})
		waf.ProxyHTTP(w, r, hostKey, bu, "1.2.3.4", ctx, weblog, hs)
	}))
	defer front.Close()

	// 先把懒初始化跑掉，排除首次建代理的影响
	if resp, err := http.Get(front.URL + "/fast"); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// 开一条 2 秒的流
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		resp, err := http.Get(front.URL + "/stream")
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	time.Sleep(300 * time.Millisecond) // 确保流已经在传输中

	// 流还开着时，访问同站点另一个页面
	start := time.Now()
	resp, err := http.Get(front.URL + "/fast")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("流传输期间同站点其他页面直接失败: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-streamDone

	t.Logf("流传输期间，同站点另一个页面耗时 %v", elapsed.Round(time.Millisecond))
	if elapsed > 500*time.Millisecond {
		t.Errorf("整站被一条流堵住：另一个页面等了 %v（后端本身是立即返回的）", elapsed.Round(time.Millisecond))
	}
	_ = hs
}

// 客户端中途放弃时，上游响应体必须被关闭（否则连接泄漏，反复几次整站打不开）
func TestStreamProcessorClosesUpstreamBody(t *testing.T) {
	closed := make(chan struct{})
	src := &closeTrackingReader{data: []byte("data: {\"a\":1}\n\n"), closed: closed}
	sp := newStreamProcessorForTest(src)

	buf := make([]byte, 8)
	sp.Read(buf) // 只读一点点就放弃
	if err := sp.Close(); err != nil {
		t.Fatalf("Close 返回错误: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Error("StreamProcessor.Close() 没有关闭上游响应体 —— 连接会泄漏")
	}
}

type closeTrackingReader struct {
	data   []byte
	pos    int
	closed chan struct{}
}

func (c *closeTrackingReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *closeTrackingReader) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
