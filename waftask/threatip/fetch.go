package threatip

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// fetchClient 威胁情报订阅拉取用的 HTTP 客户端(独立超时，参照 wafowasp/upgrader.go 的模式)
var fetchClient = &http.Client{Timeout: 2 * time.Minute}

// maxFetchBytes 单次拉取的响应体上限(防超大/投毒响应耗尽内存)：64MB
const maxFetchBytes = 64 * 1024 * 1024

// Fetch 拉取订阅源原始内容。限制最大读取字节数，返回原始 body 字节。
// 注意：调用方需确保 url 已登记进对外访问白名单(见 CLAUDE.md)，且订阅默认关闭、由用户显式启用。
func Fetch(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SamWaf-ThreatIP")
	resp, err := fetchClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取失败，HTTP 状态码: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return nil, err
	}
	return data, nil
}
