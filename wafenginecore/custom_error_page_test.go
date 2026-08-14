package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// 说明：这套用例只针对「后端真实返回的状态码」这条路径（modifyResponse → applyCustomErrorPage）。
// WAF 自身的拦截走 EchoErrorInfo，是另一条独立路径，不读 ContentPriority，因此不在此处覆盖。

const testTemplate = `<html><body>code=[[.SAMWAF_BACKEND_CODE]] status=[[.SAMWAF_BACKEND_STATUS]] uuid=[[.SAMWAF_REQ_UUID]] body=[[.SAMWAF_BACKEND_BODY]]</body></html>`

// newBackendResp 造一个"后端真实返回"的响应
func newBackendResp(statusCode int, status string, contentType string, body []byte) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		StatusCode:    statusCode,
		Status:        status,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func gzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("gzip 写入失败: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip 关闭失败: %v", err)
	}
	return buf.Bytes()
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	return b
}

func page(responseCode string, priority string) *model.BlockingPage {
	return &model.BlockingPage{
		BlockingType:    "other_block",
		ResponseCode:    responseCode,
		ResponseHeader:  `[{"name":"Content-Type","value":"text/html"}]`,
		ResponseContent: testTemplate,
		ContentPriority: priority,
	}
}

// TestResolveCustomErrorPage_ByStatusCode 验证 400/403/404/500/502 等各状态码都能各自命中自己的配置，
// 没配的状态码不会被误命中。
func TestResolveCustomErrorPage_ByStatusCode(t *testing.T) {
	hostSafe := &wafenginmodel.HostSafe{
		BlockingPage: map[string]model.BlockingPage{
			"400": *page("400", ""),
			"403": *page("403", ""),
			"404": *page("404", ""),
			"500": *page("500", ""),
			"502": *page("502", ""),
		},
	}
	globalSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{}}

	for _, code := range []int{400, 403, 404, 500, 502} {
		got := resolveCustomErrorPage(hostSafe, globalSafe, code)
		if got == nil {
			t.Fatalf("状态码 %d 应命中自定义错误页，实际未命中", code)
		}
		if got.ResponseCode != strconv.Itoa(code) {
			t.Fatalf("状态码 %d 命中了错误的配置: %s", code, got.ResponseCode)
		}
	}

	// 未配置的状态码不应命中
	for _, code := range []int{200, 301, 302, 401, 503} {
		if got := resolveCustomErrorPage(hostSafe, globalSafe, code); got != nil {
			t.Fatalf("状态码 %d 未配置，不应命中，实际命中 %s", code, got.ResponseCode)
		}
	}
}

// TestResolveCustomErrorPage_HostBeatsGlobal 网站级配置优先于全局级；网站级没有时回落全局级。
func TestResolveCustomErrorPage_HostBeatsGlobal(t *testing.T) {
	hostPage := *page("500", "")
	hostPage.BlockingPageName = "host"
	globalPage := *page("500", "")
	globalPage.BlockingPageName = "global"
	globalOnly := *page("502", "")
	globalOnly.BlockingPageName = "global-502"

	hostSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{"500": hostPage}}
	globalSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{"500": globalPage, "502": globalOnly}}

	if got := resolveCustomErrorPage(hostSafe, globalSafe, 500); got == nil || got.BlockingPageName != "host" {
		t.Fatalf("500 应优先取网站级配置，实际 %+v", got)
	}
	if got := resolveCustomErrorPage(hostSafe, globalSafe, 502); got == nil || got.BlockingPageName != "global-502" {
		t.Fatalf("502 网站级没有，应回落全局级，实际 %+v", got)
	}
}

// TestResolveCustomErrorPage_NilSafe 全局站点还没加载出来时不应 panic。
func TestResolveCustomErrorPage_NilSafe(t *testing.T) {
	if got := resolveCustomErrorPage(nil, nil, 500); got != nil {
		t.Fatalf("两侧都为 nil 时应返回 nil，实际 %+v", got)
	}
	hostSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{"500": *page("500", "")}}
	if got := resolveCustomErrorPage(hostSafe, nil, 500); got == nil {
		t.Fatal("全局为 nil 时仍应能命中网站级配置")
	}
}

// TestApplyCustomErrorPage_DefaultOverwrites 默认（samwaf / 空值）行为：
// 后端 400/500 即便带了 JSON body，也一律被模版覆盖——这是修复前的行为，必须保持不变。
func TestApplyCustomErrorPage_DefaultOverwrites(t *testing.T) {
	for _, priority := range []string{"", model.BlockingPageContentPrioritySamwaf} {
		for _, code := range []int{400, 403, 404, 500, 502} {
			backendBody := []byte(`{"code":` + strconv.Itoa(code) + `,"message":"backend says no"}`)
			resp := newBackendResp(code, strconv.Itoa(code)+" Err", "application/json", backendBody)

			result := applyCustomErrorPage(resp, page("", priority), code, resp.Status, "uuid-1")

			if !result.TemplateApplied {
				t.Fatalf("priority=%q code=%d 应使用模版覆盖", priority, code)
			}
			got := string(readBody(t, resp))
			if !strings.Contains(got, "code="+strconv.Itoa(code)) {
				t.Fatalf("priority=%q code=%d 模版未被渲染: %s", priority, code, got)
			}
			if resp.StatusCode != code {
				t.Fatalf("未配置 response_code 时应沿用后端状态码 %d，实际 %d", code, resp.StatusCode)
			}
			if string(result.BackendBody) != string(backendBody) {
				t.Fatalf("后端原始 body 应被完整带出用于日志，实际 %q", result.BackendBody)
			}
		}
	}
}

// TestApplyCustomErrorPage_BackendFirstPassthrough 「优先后端响应」：
// 后端有内容时状态码/Content-Type/响应体一个字节都不能动。
func TestApplyCustomErrorPage_BackendFirstPassthrough(t *testing.T) {
	for _, code := range []int{400, 403, 404, 500, 502} {
		backendBody := []byte(`{"code":` + strconv.Itoa(code) + `,"message":"no permission"}`)
		resp := newBackendResp(code, strconv.Itoa(code)+" Err", "application/json", backendBody)

		result := applyCustomErrorPage(resp, page("", model.BlockingPageContentPriorityBackend), code, resp.Status, "uuid-1")

		if result.TemplateApplied {
			t.Fatalf("code=%d 后端有响应体时应透传，不应套模版", code)
		}
		if got := string(readBody(t, resp)); got != string(backendBody) {
			t.Fatalf("code=%d 响应体应原样透传，实际 %q", code, got)
		}
		if resp.StatusCode != code {
			t.Fatalf("code=%d 状态码不应被改动，实际 %d", code, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("code=%d Content-Type 不应被改动，实际 %q", code, ct)
		}
	}
}

// TestApplyCustomErrorPage_BackendFirstFallback 「优先后端响应」但后端没给响应体时，模版必须兜底。
func TestApplyCustomErrorPage_BackendFirstFallback(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"完全没有响应体", []byte("")},
		{"只有空白字符", []byte("\r\n  \t\n")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := newBackendResp(500, "500 Internal Server Error", "text/html", c.body)

			result := applyCustomErrorPage(resp, page("", model.BlockingPageContentPriorityBackend), 500, resp.Status, "uuid-1")

			if !result.TemplateApplied {
				t.Fatal("后端无响应体时应回落到自定义模版")
			}
			if got := string(readBody(t, resp)); !strings.Contains(got, "code=500") {
				t.Fatalf("模版未生效: %s", got)
			}
		})
	}
}

// TestApplyCustomErrorPage_NilBody 后端连 Body 都是 nil / NoBody 时不应 panic，并回落模版。
func TestApplyCustomErrorPage_NilBody(t *testing.T) {
	for _, body := range []io.ReadCloser{nil, http.NoBody} {
		resp := newBackendResp(502, "502 Bad Gateway", "text/html", nil)
		resp.Body = body

		result := applyCustomErrorPage(resp, page("", model.BlockingPageContentPriorityBackend), 502, resp.Status, "uuid-1")

		if !result.TemplateApplied {
			t.Fatal("无 body 时应使用模版")
		}
		if got := string(readBody(t, resp)); !strings.Contains(got, "code=502") {
			t.Fatalf("模版未生效: %s", got)
		}
	}
}

// TestApplyCustomErrorPage_ResponseCodeOverride 配置了 response_code 时以配置为准（后端 500 → 下发 503）。
func TestApplyCustomErrorPage_ResponseCodeOverride(t *testing.T) {
	resp := newBackendResp(500, "500 Internal Server Error", "text/html", []byte(""))

	applyCustomErrorPage(resp, page("503", ""), 500, resp.Status, "uuid-1")

	if resp.StatusCode != 503 {
		t.Fatalf("配置 response_code=503 时应下发 503，实际 %d", resp.StatusCode)
	}
	// 模板里拿到的仍应是后端真实状态码
	if got := string(readBody(t, resp)); !strings.Contains(got, "code=500") {
		t.Fatalf("模板变量应是后端真实状态码 500，实际 %s", got)
	}
}

// TestApplyCustomErrorPage_ResponseHeaderApplied 配置的响应头要被写进去，Content-Length 要跟模版长度对上。
func TestApplyCustomErrorPage_ResponseHeaderApplied(t *testing.T) {
	p := page("", "")
	p.ResponseHeader = `[{"name":"Content-Type","value":"text/html"},{"name":"X-Waf-Page","value":"custom"},{"name":"X-Empty","value":""}]`
	resp := newBackendResp(404, "404 Not Found", "application/json", []byte(""))

	applyCustomErrorPage(resp, p, 404, resp.Status, "uuid-1")

	body := readBody(t, resp)
	if resp.Header.Get("Content-Type") != "text/html" {
		t.Fatalf("配置的 Content-Type 未生效: %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Waf-Page") != "custom" {
		t.Fatalf("自定义响应头未生效: %q", resp.Header.Get("X-Waf-Page"))
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length(%s) 与实际响应体长度(%d) 不一致", resp.Header.Get("Content-Length"), len(body))
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("resp.ContentLength(%d) 与实际响应体长度(%d) 不一致", resp.ContentLength, len(body))
	}
}

// TestApplyCustomErrorPage_GzipBackend_TemplateDropsContentEncoding
// 后端开了 gzip 的 500：模版是明文，Content-Encoding 必须被清掉，
// 否则浏览器会拿 gzip 去解一段纯 HTML，页面直接解码失败。
func TestApplyCustomErrorPage_GzipBackend_TemplateDropsContentEncoding(t *testing.T) {
	plain := []byte(`{"code":500,"message":"boom"}`)
	resp := newBackendResp(500, "500 Internal Server Error", "application/json", gzipBytes(t, plain))
	resp.Header.Set("Content-Encoding", "gzip")

	result := applyCustomErrorPage(resp, page("", ""), 500, resp.Status, "uuid-1")

	if !result.TemplateApplied {
		t.Fatal("默认模式下应套模版")
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Fatalf("下发明文模版时 Content-Encoding 必须清掉，实际 %q", enc)
	}
	body := readBody(t, resp)
	if !strings.Contains(string(body), "code=500") {
		t.Fatalf("响应体应是明文模版，实际 %q", body)
	}
	// 模板变量与日志拿到的应是解压后的明文，而不是 gzip 二进制
	if !strings.Contains(string(body), string(plain)) {
		t.Fatalf("SAMWAF_BACKEND_BODY 应是解压后的明文，实际 %q", body)
	}
	if string(result.BackendBody) != string(plain) {
		t.Fatalf("日志用的后端 body 应是解压后的明文，实际 %q", result.BackendBody)
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length 应等于模版长度，实际 %s vs %d", resp.Header.Get("Content-Length"), len(body))
	}
}

// TestApplyCustomErrorPage_GzipBackend_PassthroughKeepsBytes
// 后端开了 gzip 且选「优先后端响应」：原始压缩字节与 Content-Encoding 都必须原样保留。
func TestApplyCustomErrorPage_GzipBackend_PassthroughKeepsBytes(t *testing.T) {
	plain := []byte(`{"code":403,"message":"no permission"}`)
	raw := gzipBytes(t, plain)
	resp := newBackendResp(403, "403 Forbidden", "application/json", raw)
	resp.Header.Set("Content-Encoding", "gzip")

	result := applyCustomErrorPage(resp, page("", model.BlockingPageContentPriorityBackend), 403, resp.Status, "uuid-1")

	if result.TemplateApplied {
		t.Fatal("后端有内容时应透传")
	}
	if got := readBody(t, resp); !bytes.Equal(got, raw) {
		t.Fatal("透传时压缩字节必须逐字节保留")
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("透传时 Content-Encoding 必须保留，实际 %q", resp.Header.Get("Content-Encoding"))
	}
	if string(result.BackendBody) != string(plain) {
		t.Fatalf("日志用的 body 应是解压后的明文，实际 %q", result.BackendBody)
	}
}

// TestApplyCustomErrorPage_GzipEmptyBody_FallsBackToTemplate
// 关键回归点：gzip 后的"空 body"也有二十来字节，若按原始字节判空会永远认为"后端有内容"，
// 导致「优先后端响应」在压缩站点上永远不回落模版。必须按解压后的明文判定。
func TestApplyCustomErrorPage_GzipEmptyBody_FallsBackToTemplate(t *testing.T) {
	raw := gzipBytes(t, []byte(""))
	if len(raw) == 0 {
		t.Fatal("前置假设失败：gzip 空内容也应产生非空字节")
	}
	resp := newBackendResp(500, "500 Internal Server Error", "text/html", raw)
	resp.Header.Set("Content-Encoding", "gzip")

	result := applyCustomErrorPage(resp, page("", model.BlockingPageContentPriorityBackend), 500, resp.Status, "uuid-1")

	if !result.TemplateApplied {
		t.Fatal("后端 body 解压后为空，应回落到自定义模版")
	}
	if got := string(readBody(t, resp)); !strings.Contains(got, "code=500") {
		t.Fatalf("模版未生效: %s", got)
	}
}

// TestDecodeResponseBodyBytes 解码器本身：识别 gzip、放过未压缩、解压失败时回退原始字节。
func TestDecodeResponseBodyBytes(t *testing.T) {
	plain := []byte("hello 你好")

	if got, err := decodeResponseBodyBytes("", plain); err != nil || string(got) != string(plain) {
		t.Fatalf("未压缩内容应原样返回，got=%q err=%v", got, err)
	}
	if got, err := decodeResponseBodyBytes("gzip", gzipBytes(t, plain)); err != nil || string(got) != string(plain) {
		t.Fatalf("gzip 解压失败 got=%q err=%v", got, err)
	}
	// 声明了 gzip 但内容不是 gzip：应返回错误并回退原始字节，调用方据此按原始字节处理
	bad := []byte("not gzip at all")
	got, err := decodeResponseBodyBytes("gzip", bad)
	if err == nil {
		t.Fatal("非法 gzip 内容应返回错误")
	}
	if string(got) != string(bad) {
		t.Fatalf("解压失败时应回退原始字节，实际 %q", got)
	}
	// 未知编码原样返回
	if got, err := decodeResponseBodyBytes("weird-encoding", plain); err != nil || string(got) != string(plain) {
		t.Fatalf("未知编码应原样返回，got=%q err=%v", got, err)
	}
}
