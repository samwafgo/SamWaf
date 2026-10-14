package wafhealth

import (
	"SamWaf/model"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Passed  = "passed"
	Failed  = "failed"
	Skipped = "skipped"
)

type Result struct {
	BackendID   string `json:"backend_id"`
	BackIP      string `json:"back_ip"`
	BackPort    int    `json:"back_port"`
	DialAddress string `json:"dial_address"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	RequestHost string `json:"request_host"`
	StatusCode  int    `json:"status_code"`
	ElapsedMS   int64  `json:"elapsed_ms"`
	Outcome     string `json:"outcome"`
	ErrorReason string `json:"error_reason"`
}

type transportEntry struct {
	transport *http.Transport
	users     int
	retired   bool
}

var (
	transportMu   sync.Mutex
	transportPool = make(map[string]*transportEntry)
)

func newTransport(dialAddr string, guard func(address string) error) *http.Transport {
	dialer := &net.Dialer{}
	if guard != nil {
		dialer.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			return guard(address)
		}
	}
	return &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddr)
		},
	}
}

func acquireTransport(dialAddr string, pooled bool, guard func(address string) error) (*http.Transport, func()) {
	if !pooled {
		t := newTransport(dialAddr, guard)
		return t, t.CloseIdleConnections
	}
	transportMu.Lock()
	entry := transportPool[dialAddr]
	if entry == nil {
		entry = &transportEntry{transport: newTransport(dialAddr, nil)}
		transportPool[dialAddr] = entry
	}
	entry.users++
	transportMu.Unlock()
	return entry.transport, func() {
		transportMu.Lock()
		defer transportMu.Unlock()
		entry.users--
		if entry.retired && entry.users == 0 {
			entry.transport.CloseIdleConnections()
		}
	}
}

// CleanupTransports retires pools for targets no longer used by scheduled probes.
func CleanupTransports(validDialAddrs map[string]struct{}) {
	transportMu.Lock()
	defer transportMu.Unlock()
	for addr, entry := range transportPool {
		if _, ok := validDialAddrs[addr]; !ok {
			delete(transportPool, addr)
			entry.retired = true
			entry.transport.CloseIdleConnections()
		}
	}
}

// Probe performs one request; health counters belong to its caller.
func Probe(ctx context.Context, host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string, pooled bool) Result {
	return probe(ctx, host, ip, port, config, backendID, pooled, nil)
}

// ProbeWithDialGuard checks each resolved address before connecting with a temporary transport.
func ProbeWithDialGuard(ctx context.Context, host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string, guard func(address string) error) Result {
	return probe(ctx, host, ip, port, config, backendID, false, guard)
}

func probe(ctx context.Context, host model.Hosts, ip string, port int, config model.HealthyConfig, backendID string, pooled bool, guard func(address string) error) Result {
	result := Result{BackendID: backendID, BackIP: ip, BackPort: port, Method: config.CheckMethod, Outcome: Skipped}
	checkPath := config.CheckPath
	if checkPath == "" {
		checkPath = "/"
	}
	mainHost := host.Remote_host
	if host.Host == "*" {
		mainHost = strings.ReplaceAll(mainHost, "*", host.Remote_ip)
	}
	result.URL = mainHost + ":" + strconv.Itoa(host.Remote_port) + checkPath
	parsedURL, err := url.Parse(result.URL)
	if err != nil || parsedURL.Host == "" || strings.Contains(parsedURL.Host, "*") {
		result.ErrorReason = "URL 无效或包含未解析通配符"
		return result
	}
	if host.IsEnableLoadBalance > 0 {
		result.DialAddress = net.JoinHostPort(ip, strconv.Itoa(port))
	} else if host.Remote_ip != "" {
		result.DialAddress = net.JoinHostPort(host.Remote_ip, strconv.Itoa(host.Remote_port))
	} else {
		result.DialAddress = parsedURL.Host
	}

	transport, release := acquireTransport(result.DialAddress, pooled, guard)
	defer release()
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(config.ResponseTime)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, config.CheckMethod, result.URL, nil)
	if err != nil {
		result.Outcome = Failed
		result.ErrorReason = "创建请求失败: " + err.Error()
		return result
	}
	if host.IsTransBackDomain == 1 {
		hostPort := strings.Split(host.Remote_host, ":")
		if len(hostPort) == 2 && req.Host != hostPort[0] {
			req.Host = hostPort[0]
		}
	}
	result.Method = req.Method
	result.RequestHost = req.Host
	start := time.Now()
	resp, err := (&http.Client{Transport: transport}).Do(req)
	result.ElapsedMS = time.Since(start).Milliseconds()
	result.Outcome = Failed
	if err != nil {
		result.ErrorReason = "请求失败: " + err.Error()
		return result
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	for _, code := range ParseExpectedCodes(config.ExpectedCodes) {
		if resp.StatusCode == code {
			result.Outcome = Passed
			return result
		}
	}
	result.ErrorReason = result.URL + "状态码不符合预期: " + strconv.Itoa(resp.StatusCode)
	return result
}

// ParseExpectedCodes keeps the scheduled task's fallback for empty or unparseable lists.
func ParseExpectedCodes(codesStr string) []int {
	parts := strings.Split(codesStr, ",")
	codes := make([]int, 0, len(parts))
	for _, part := range parts {
		if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			codes = append(codes, code)
		}
	}
	if len(codes) == 0 {
		return []int{200, 201, 202, 203, 204, 301, 302, 303, 307, 308}
	}
	return codes
}
