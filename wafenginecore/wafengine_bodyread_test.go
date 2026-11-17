package wafenginecore

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newBodyRequest 构造一个携带请求体的测试请求；chunked 时把 ContentLength 置为 -1，
// 模拟 Go 在分块传输下的真实表现。
func newBodyRequest(t *testing.T, payload []byte, chunked bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://xxxx.com/upload", bytes.NewReader(payload))
	if chunked {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	return req
}

// TestReadRequestBodyChunked 护栏：分块传输（ContentLength=-1）时请求体前缀可读作检测输入，
// 且 r.Body 还原完整，下游转发一字节不丢。
// 反向验证过：在 helper 入口恢复"ContentLength<=0 不读"的旧判断后，本用例变红。
func TestReadRequestBodyChunked(t *testing.T) {
	payload := []byte("union select password from admin-- " + strings.Repeat("a", 64))
	req := newBodyRequest(t, payload, true)
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, false)
	if !bytes.Contains(got, []byte("union select")) {
		t.Fatalf("chunked请求体未进入检测输入: %q", got)
	}

	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("chunked转发不完整: 读到%d字节，期望%d字节", len(rest), len(payload))
	}
}

// TestReadRequestBodyDetectsBeyondRecordLimit 护栏：攻击特征出现在 GCONFIG_RECORD_MAX_BODY_LENGTH
// （默认 2048，日志落库上限）之后时，仍被检测输入覆盖——检测上限与日志上限是两条独立的线。
// 反向验证过：把 helper 的常规分支读取上限改回 GCONFIG_RECORD_MAX_BODY_LENGTH 后，本用例变红。
func TestReadRequestBodyDetectsBeyondRecordLimit(t *testing.T) {
	attack := "' OR '1'='1"
	// 攻击特征放在 2048 字节之后
	payload := append(bytes.Repeat([]byte("A"), 3000), []byte(attack)...)
	req := newBodyRequest(t, payload, false)
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, false)
	if !bytes.Contains(got, []byte(attack)) {
		t.Fatalf("2048字节之后的攻击特征未进入检测输入，检测输入长度=%d", len(got))
	}

	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("转发内容与原始报文不一致: 读到%d字节，期望%d字节", len(rest), len(payload))
	}
}

// TestReadRequestBodyLargeUploadForwardIntact 护栏：超过检测预算（1MB）的大上传，
// 检测输入只取前缀封顶，但 r.Body 还原完整、下游转发一字节不丢。
// 反向验证过：把常规分支的 MultiReader 还原换成只留前缀后，本用例变红。
func TestReadRequestBodyLargeUploadForwardIntact(t *testing.T) {
	payload := bytes.Repeat([]byte("Z"), 2<<20) // 2 MB
	req := newBodyRequest(t, payload, false)
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, false)
	if int64(len(got)) != detectBodyReadLimit {
		t.Fatalf("检测输入长度=%d，期望封顶%d", len(got), detectBodyReadLimit)
	}

	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("大上传转发不完整: 读到%d字节，期望%d字节", len(rest), len(payload))
	}
}

// TestReadRequestBodyContentEncoding 护栏：压缩请求体的检测输入是解压后内容，
// r.Body 还原为原始压缩流供下游转发。
func TestReadRequestBodyContentEncoding(t *testing.T) {
	raw := []byte("username=admin' AND 1=1--&password=x")
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://xxxx.com/login", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, false)
	if !bytes.Contains(got, []byte("AND 1=1")) {
		t.Fatalf("解压后的攻击特征未进入检测输入: %q", got)
	}

	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, compressed.Bytes()) {
		t.Fatalf("压缩流还原不完整: 读到%d字节，期望%d字节", len(rest), compressed.Len())
	}
}

// TestReadRequestBodyEmpty 空请求体与 GET 场景直接返回 nil，不触碰 r.Body。
func TestReadRequestBodyEmpty(t *testing.T) {
	waf := &WafEngine{}

	req := httptest.NewRequest(http.MethodGet, "http://xxxx.com/", nil)
	if got := waf.readRequestBodyForDetect(req, false); got != nil {
		t.Fatalf("GET请求应返回nil，得到%q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "http://xxxx.com/", nil)
	req.Body = http.NoBody
	if got := waf.readRequestBodyForDetect(req, false); got != nil {
		t.Fatalf("NoBody应返回nil，得到%q", got)
	}
}

// TestReadRequestBodyCacheBranchFullRead 缓存分支保持全量读取（缓存键与内容需要完整请求体）。
func TestReadRequestBodyCacheBranchFullRead(t *testing.T) {
	payload := bytes.Repeat([]byte("C"), 2<<20) // 2 MB
	req := newBodyRequest(t, payload, false)
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, true)
	if int64(len(got)) != int64(len(payload)) {
		t.Fatalf("缓存分支应全量读取，得到%d字节，期望%d字节", len(got), len(payload))
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, payload) {
		t.Fatalf("缓存分支转发不完整: 读到%d字节，期望%d字节", len(rest), len(payload))
	}
}
