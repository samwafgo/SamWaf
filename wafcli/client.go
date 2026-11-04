package wafcli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"SamWaf/global"
	"SamWaf/utils"
)

const hostAPI = "/api/v1/wafhost/host/"
const maxResponseBytes = 32 << 20

type apiClient struct {
	baseURL string
	key     string
	http    *http.Client
	wait    time.Duration
}

func newLocalClient(wait time.Duration) (*apiClient, error) {
	key := strings.TrimSpace(os.Getenv("SAMWAF_API_KEY"))
	if key == "" {
		keyPath := filepath.Join(utils.GetCurrentDir(), "data", ".keys", "cli_api_key")
		if err := rejectKeySymlinks(keyPath); err != nil {
			return nil, fail(ExitAuth, errors.New("Key文件路径不正确，请执行 samwaf apikey init"))
		}
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fail(ExitAuth, errors.New("请先执行 samwaf apikey init"))
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" || strings.ContainsAny(key, "\r\n") {
		return nil, fail(ExitAuth, errors.New("API Key 为空或格式不正确，请执行 samwaf apikey init"))
	}
	scheme := "http"
	if global.GWAF_SSL_ENABLE && global.GWAF_SSL_FORCE_HTTPS {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://127.0.0.1:%d", scheme, global.GWAF_LOCAL_SERVER_PORT)
	if global.GWAF_SECURITY_ENTRY_ENABLE {
		entry := strings.Trim(global.GWAF_SECURITY_ENTRY_PATH, "/")
		if entry != "" {
			base += "/" + url.PathEscape(entry)
		}
	}
	return newAPIClient(base, key, wait), nil
}

func newAPIClient(base, key string, wait time.Duration) *apiClient {
	tr := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		// 仅连接固定回环地址，允许管理端使用自签名证书。
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &apiClient{baseURL: strings.TrimRight(base, "/"), key: key, wait: wait,
		http: &http.Client{Transport: tr, Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (a *apiClient) call(ctx context.Context, method, path string, body any, out any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return fail(ExitUsage, errors.New("无法编码请求JSON"))
		}
	}
	deadline := time.Now().Add(a.wait)
	for {
		requestCtx := ctx
		cancel := func() {}
		if a.wait > 0 {
			requestCtx, cancel = context.WithDeadline(ctx, deadline)
		}
		req, e := http.NewRequestWithContext(requestCtx, method, a.baseURL+path, bytes.NewReader(payload))
		if e != nil {
			cancel()
			return fail(ExitUsage, errors.New("管理端地址格式错误"))
		}
		req.Header.Set("X-API-Key", a.key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := a.http.Do(req)
		if e != nil {
			cancel()
			// 只重试尚未建立连接的请求，避免重复提交写操作。
			var op *net.OpError
			retryable := errors.As(e, &op) && op.Op == "dial"
			if retryable && a.wait > 0 && time.Now().Before(deadline) {
				delay := time.Until(deadline)
				if delay > time.Second {
					delay = time.Second
				}
				select {
				case <-ctx.Done():
					return fail(ExitUnavailable, errors.New("操作已取消"))
				case <-time.After(delay):
				}
				continue
			}
			return fail(ExitUnavailable, fmt.Errorf("无法连接 SamWaf 管理端，请检查服务、端口与HTTPS配置；可使用 --wait 60s 等待启动"))
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		cancel()
		if e != nil || len(b) > maxResponseBytes {
			return fail(ExitFailed, errors.New("读取管理端响应失败或响应过大"))
		}
		if resp.StatusCode != http.StatusOK {
			hint := ""
			if resp.StatusCode == 403 {
				hint = "，请检查管理端IP白名单、域名白名单与安全入口"
			}
			return fail(ExitFailed, fmt.Errorf("管理端返回HTTP %d%s", resp.StatusCode, hint))
		}
		var envelope struct {
			Code *int            `json:"code"`
			Data json.RawMessage `json:"data"`
			Msg  string          `json:"msg"`
		}
		if json.Unmarshal(b, &envelope) != nil || envelope.Code == nil {
			return fail(ExitFailed, errors.New("管理端响应不是有效的API结果，请检查安全入口和HTTPS配置"))
		}
		if *envelope.Code != 0 {
			code := ExitFailed
			if *envelope.Code == -999 {
				code = ExitAuth
			}
			msg := envelope.Msg
			if msg == "" {
				msg = "管理端拒绝操作"
			}
			msg = strings.ReplaceAll(msg, a.key, "[REDACTED]")
			return fail(code, errors.New(msg))
		}
		if out != nil && json.Unmarshal(envelope.Data, out) != nil {
			return fail(ExitFailed, errors.New("管理端返回的数据格式不正确"))
		}
		return nil
	}
}

type siteRecord map[string]json.RawMessage

func recordString(m siteRecord, k string) string {
	var v string
	_ = json.Unmarshal(m[k], &v)
	return v
}
func recordInt(m siteRecord, k string) int { var v int; _ = json.Unmarshal(m[k], &v); return v }

func (a *apiClient) list(ctx context.Context) ([]siteRecord, error) {
	items := []siteRecord{}
	for page := 1; ; page++ {
		var result struct {
			List  []siteRecord `json:"list"`
			Total int64        `json:"total"`
		}
		if err := a.call(ctx, http.MethodPost, hostAPI+"list", map[string]int{"pageIndex": page, "pageSize": 100}, &result); err != nil {
			return nil, err
		}
		if len(result.List) == 0 {
			break
		}
		items = append(items, result.List...)
		if int64(len(items)) >= result.Total {
			break
		}
		if page >= 10000 {
			return nil, fail(ExitFailed, errors.New("站点分页数量超过上限"))
		}
	}
	return items, nil
}

func (a *apiClient) detail(ctx context.Context, code string) (siteRecord, error) {
	var m siteRecord
	if err := a.call(ctx, http.MethodGet, hostAPI+"detail?"+url.Values{"code": {code}}.Encode(), nil, &m); err != nil {
		return nil, err
	}
	if recordString(m, "code") == "" {
		return nil, fail(ExitNotFound, errors.New("站点不存在"))
	}
	return m, nil
}
