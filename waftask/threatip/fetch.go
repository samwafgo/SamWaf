package threatip

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchClient 威胁情报订阅拉取用的 HTTP 客户端(独立超时，参照 wafowasp/upgrader.go 的模式)
var fetchClient = &http.Client{Timeout: 2 * time.Minute}

// maxFetchBytes 单次拉取的响应体上限(防超大/投毒响应耗尽内存)：64MB
const maxFetchBytes = 64 * 1024 * 1024

// bodyPeekLen 非 200 时截取响应正文做摘要的长度(用于区分"真的挂了"与"返回了HTML错误页/验证页")
const bodyPeekLen = 200

// FetchStat 一次拉取的可观测信息，供调用方打日志/回写状态。
type FetchStat struct {
	StatusCode int           // HTTP 状态码，0 表示连接阶段就失败
	Bytes      int           // 实际读取到的字节数
	Elapsed    time.Duration // 整体耗时(含连接、TLS、读完 body)
}

// Fetch 拉取订阅源原始内容。限制最大读取字节数，返回原始 body 字节。
// 注意：调用方需确保 url 已登记进对外访问白名单(见 CLAUDE.md)，且订阅默认关闭、由用户显式启用。
func Fetch(url string) ([]byte, error) {
	data, _, err := FetchWithStat(url)
	return data, err
}

// FetchWithStat 与 Fetch 相同，但额外返回本次拉取的状态码/字节数/耗时。
// 失败时错误信息里会带上 URL、耗时与(非 200 时的)响应正文摘要——这条链路以前失败是完全静默的，
// 用户只能看到"没反应"，所以这里刻意把上下文塞足，便于日志与"上次状态"里直接看出原因。
func FetchWithStat(url string) ([]byte, FetchStat, error) {
	start := time.Now()
	stat := FetchStat{}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		stat.Elapsed = time.Since(start)
		return nil, stat, fmt.Errorf("构造请求失败(url=%s): %v", url, err)
	}
	req.Header.Set("User-Agent", "SamWaf-ThreatIP")

	resp, err := fetchClient.Do(req)
	if err != nil {
		stat.Elapsed = time.Since(start)
		return nil, stat, fmt.Errorf("请求失败(url=%s, 耗时=%s): %v", url, stat.Elapsed.Round(time.Millisecond), err)
	}
	defer resp.Body.Close()
	stat.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		peek, _ := io.ReadAll(io.LimitReader(resp.Body, bodyPeekLen))
		stat.Elapsed = time.Since(start)
		return nil, stat, fmt.Errorf("HTTP 状态码 %d(url=%s, 耗时=%s, 正文摘要=%q)",
			resp.StatusCode, url, stat.Elapsed.Round(time.Millisecond), summarize(peek))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	stat.Bytes = len(data)
	stat.Elapsed = time.Since(start)
	if err != nil {
		return nil, stat, fmt.Errorf("读取响应失败(url=%s, 已读=%d字节, 耗时=%s): %v",
			url, stat.Bytes, stat.Elapsed.Round(time.Millisecond), err)
	}
	return data, stat, nil
}

// summarize 把响应片段压成单行摘要(去换行、压空白)，避免污染日志与 last_status
func summarize(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}
