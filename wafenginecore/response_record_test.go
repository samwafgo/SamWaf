package wafenginecore

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"SamWaf/common/queue"
	"SamWaf/global"
	"SamWaf/innerbean"
)

// 通过真实代理验证正文采集与客户端响应完整性；限长在持久化副本中验证。

// setupRecordResp 装好采集开关与日志队列，返回一个取日志的函数。
func setupRecordResp(t *testing.T, recordResp, maxLen int64) func() *innerbean.WebLog {
	t.Helper()
	oldQueue := global.GQEQUE_LOG_DB
	oldResp := global.GCONFIG_RECORD_RESP
	oldMax := global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH
	global.GQEQUE_LOG_DB = queue.NewQueue()
	global.GCONFIG_RECORD_RESP = recordResp
	global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = maxLen
	t.Cleanup(func() {
		global.GQEQUE_LOG_DB = oldQueue
		global.GCONFIG_RECORD_RESP = oldResp
		global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = oldMax
	})
	return func() *innerbean.WebLog {
		t.Helper()
		v, ok := global.GQEQUE_LOG_DB.Dequeue()
		if !ok {
			t.Fatal("访问日志没有入队")
		}
		lg, ok := v.(*innerbean.WebLog)
		if !ok {
			t.Fatalf("入队日志类型异常: %T", v)
		}
		return lg
	}
}

// startGzipBackend 后端返回 gzip 压缩体（压缩后 < 4096，解压后 > 4096）。
func startGzipBackend(t *testing.T, content string) *httptest.Server {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()
	if len(compressed) >= 4096 {
		t.Fatalf("测试前提不成立：压缩后 %d 字节应小于 4096", len(compressed))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(compressed)))
		_, _ = w.Write(compressed)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startChunkedBackend 后端分块下发（响应无 Content-Length，代理侧 ContentLength=-1）。
func startChunkedBackend(t *testing.T, content string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		half := len(content) / 2
		_, _ = w.Write([]byte(content[:half]))
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		_, _ = w.Write([]byte(content[half:]))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startFixedLengthBackend 后端返回已知 Content-Length 的大正文。
func startFixedLengthBackend(t *testing.T, content string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write([]byte(content))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// doThroughWaf 把请求走一遍真实的 modifyResponse，返回客户端收到的正文。
func doThroughWaf(t *testing.T, front *httptest.Server, acceptEncoding string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if acceptEncoding != "" {
		// 显式声明后 Go 的 Transport 不再自动解压，代理拿到的就是压缩后的原始字节
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// gzip 传输：压缩后不足 4096、解压后超过 4096。采集到的是解码后的完整正文。
func TestResponseRecordGzipDecodedBeyondLimit(t *testing.T) {
	takeLog := setupRecordResp(t, 1, 4096)

	content := strings.Repeat("gzip-payload-", 1000) // 远大于 4096
	backend := startGzipBackend(t, content)
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine("gziphost", "gzip.example.com:443", bufferingOn)
	front := startWafFront(t, waf, "gziphost", target, bufferingOn)

	clientBody := doThroughWaf(t, front, "gzip")
	lg := takeLog()

	if lg.RES_BODY != content {
		t.Fatalf("采集到的响应正文不是解码后的完整内容：长度 %d，期望 %d", len(lg.RES_BODY), len(content))
	}
	if !bytes.Equal(lg.SrcByteResBody, []byte(content)) {
		t.Fatalf("SrcByteResBody 与解码正文不一致：长度 %d，期望 %d", len(lg.SrcByteResBody), len(content))
	}
	// 客户端拿到的仍是可正常解压的 gzip 字节，正文一个不少
	zr, err := gzip.NewReader(bytes.NewReader(clientBody))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(decompressed) != content {
		t.Fatalf("客户端正文不完整：长度 %d，期望 %d", len(decompressed), len(content))
	}
}

// chunked 传输：代理侧 ContentLength=-1，同样要采到完整正文。
func TestResponseRecordChunked(t *testing.T) {
	takeLog := setupRecordResp(t, 1, 4096)

	content := strings.Repeat("chunked-payload-", 1000)
	backend := startChunkedBackend(t, content)
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine("chunkhost", "chunk.example.com:443", bufferingOn)
	front := startWafFront(t, waf, "chunkhost", target, bufferingOn)

	clientBody := doThroughWaf(t, front, "")
	lg := takeLog()

	if lg.RES_BODY != content {
		t.Fatalf("chunked 响应未采到完整正文：长度 %d，期望 %d", len(lg.RES_BODY), len(content))
	}
	if !bytes.Equal(lg.SrcByteResBody, []byte(content)) {
		t.Fatalf("SrcByteResBody 与正文不一致：长度 %d，期望 %d", len(lg.SrcByteResBody), len(content))
	}
	if string(clientBody) != content {
		t.Fatalf("客户端正文不完整：长度 %d，期望 %d", len(clientBody), len(content))
	}
}

// 已知长度的大正文仍采集完整快照。
func TestResponseRecordKnownLargeBody(t *testing.T) {
	takeLog := setupRecordResp(t, 1, 4096)

	content := strings.Repeat("large-payload-", 1000)
	backend := startFixedLengthBackend(t, content)
	target, _ := url.Parse(backend.URL)
	waf := newBufferingTestEngine("largehost", "large.example.com:443", bufferingOn)
	front := startWafFront(t, waf, "largehost", target, bufferingOn)

	clientBody := doThroughWaf(t, front, "")
	lg := takeLog()

	if lg.RES_BODY != content {
		t.Fatalf("已知长度的大正文未采到完整内容：长度 %d，期望 %d", len(lg.RES_BODY), len(content))
	}
	if !bytes.Equal(lg.SrcByteResBody, []byte(content)) {
		t.Fatalf("SrcByteResBody 与正文不一致：长度 %d，期望 %d", len(lg.SrcByteResBody), len(content))
	}
	if string(clientBody) != content {
		t.Fatalf("客户端正文不完整：长度 %d，期望 %d", len(clientBody), len(content))
	}
}

// 开关关闭 / 上限为 0 / 上限为负数：普通响应不采正文，但访问日志本身照常记录。
func TestResponseRecordDisabled(t *testing.T) {
	cases := []struct {
		name       string
		recordResp int64
		maxLen     int64
	}{
		{"record_resp 关闭", 0, 4096},
		{"上限为 0", 1, 0},
		{"上限为负数", 1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			takeLog := setupRecordResp(t, tc.recordResp, tc.maxLen)

			// 以未知长度响应校验禁用条件。
			content := "small-payload"
			backend := startChunkedBackend(t, content)
			target, _ := url.Parse(backend.URL)
			waf := newBufferingTestEngine("offhost", "off.example.com:443", bufferingOn)
			front := startWafFront(t, waf, "offhost", target, bufferingOn)

			clientBody := doThroughWaf(t, front, "")
			lg := takeLog()

			if lg.RES_BODY != "" {
				t.Fatalf("关闭采集时仍记录了响应正文：%q", lg.RES_BODY)
			}
			if len(lg.SrcByteResBody) != 0 {
				t.Fatalf("关闭采集时仍记录了响应正文字节：%d", len(lg.SrcByteResBody))
			}
			if string(clientBody) != content {
				t.Fatalf("客户端正文被改动：%q", string(clientBody))
			}
		})
	}
}
