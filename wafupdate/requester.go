package wafupdate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// 升级通道的网络超时。
//
// 这里刻意 **不设** http.Client.Timeout：Client.Timeout 计的是"建连到响应体读完"的
// 总时长，而升级包有几十 MB，慢网用户的下载会被整包掐断。改成把超时下沉到传输层，
// 只约束"建连"和"等首字节"，body 传多久都不受限制：
//   - dialTimeout        含 DNS 解析 + TCP 建连，纯内网环境下版本检测卡死就是卡在这里
//   - tlsHandshakeTimeout 防止被中间设备劫持后 TLS 半开挂住
//   - responseHeaderTimeout 只计到服务端首字节，不含 body 传输
const (
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 8 * time.Second
	idleConnTimeout       = 30 * time.Second
)

// newUpdateHTTPClient 构造升级专用的 http.Client。
// 独立于 http.DefaultTransport —— 后者是全进程共享的，改它会波及 ACME 证书申请、
// 威胁情报订阅、CDN 回源段拉取等一堆无关模块。
func newUpdateHTTPClient(dial, tlsHandshake, respHeader time.Duration) *http.Client {
	return &http.Client{
		// 0 = 不限总时长
		Timeout: 0,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   dial,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   tlsHandshake,
			ResponseHeaderTimeout: respHeader,
			IdleConnTimeout:       idleConnTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

var defaultHTTPClient = newUpdateHTTPClient(dialTimeout, tlsHandshakeTimeout, responseHeaderTimeout)

// Requester interface allows developers to customize the method in which
// requests are made to retrieve the version and binary.
type Requester interface {
	Fetch(url string) (io.ReadCloser, error)
}

// HTTPRequester is the normal requester that is used and does an HTTP
// to the URL location requested to retrieve the specified data.
type HTTPRequester struct {
	// Client 可选；为空时使用带传输层超时的 defaultHTTPClient。
	Client *http.Client
}

// Fetch will return an HTTP request to the specified url and return
// the body of the result. An error will occur for a non 200 status code.
func (httpRequester *HTTPRequester) Fetch(url string) (io.ReadCloser, error) {
	client := httpRequester.Client
	if client == nil {
		client = defaultHTTPClient
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("bad http status from %s: %v", url, resp.Status)
	}

	return resp.Body, nil
}

// mockRequester used for some mock testing to ensure the requester contract
// works as specified.
type mockRequester struct {
	currentIndex int
	fetches      []func(string) (io.ReadCloser, error)
}

func (mr *mockRequester) handleRequest(requestHandler func(string) (io.ReadCloser, error)) {
	if mr.fetches == nil {
		mr.fetches = []func(string) (io.ReadCloser, error){}
	}
	mr.fetches = append(mr.fetches, requestHandler)
}

func (mr *mockRequester) Fetch(url string) (io.ReadCloser, error) {
	if len(mr.fetches) <= mr.currentIndex {
		return nil, fmt.Errorf("no for currentIndex %d to mock", mr.currentIndex)
	}
	current := mr.fetches[mr.currentIndex]
	mr.currentIndex++

	return current(url)
}
