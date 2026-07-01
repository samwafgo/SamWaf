package wafenginecore

import (
	"SamWaf/model"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchTamperRule(t *testing.T) {
	rules := []model.TamperRule{
		{Url: "/index.html", IsEnable: 1},
		{Url: "/app.js", IsEnable: 1},
		{Url: "/disabled.html", IsEnable: 0},
	}
	cases := []struct {
		path string
		want bool // 是否匹配到
	}{
		{"/index.html", true},
		{"/app.js", true},
		{"/disabled.html", false}, // 停用
		{"/notfound", false},
		{"/INDEX.HTML", false}, // 大小写敏感
	}
	for _, c := range cases {
		got := matchTamperRule(rules, c.path)
		if (got != nil) != c.want {
			t.Errorf("matchTamperRule(%q) matched=%v, 期望 %v", c.path, got != nil, c.want)
		}
	}
}

func TestIsTamperCandidate(t *testing.T) {
	ruleIgnore := model.TamperRule{IsEnable: 1, IgnoreQuery: 1}
	ruleStrict := model.TamperRule{IsEnable: 1, IgnoreQuery: 0}
	ruleOff := model.TamperRule{IsEnable: 0, IgnoreQuery: 1}
	cases := []struct {
		name     string
		method   string
		rawQuery string
		rule     model.TamperRule
		want     bool
	}{
		{"GET无参忽略query", "GET", "", ruleIgnore, true},
		{"GET带参忽略query照常", "GET", "v=123", ruleIgnore, true},
		{"GET带参严格跳过", "GET", "v=123", ruleStrict, false},
		{"GET无参严格", "GET", "", ruleStrict, true},
		{"POST不比对", "POST", "", ruleIgnore, false},
		{"HEAD不比对", "HEAD", "", ruleIgnore, false},
		{"规则停用", "GET", "", ruleOff, false},
	}
	for _, c := range cases {
		if got := isTamperCandidate(c.method, c.rawQuery, c.rule); got != c.want {
			t.Errorf("%s: isTamperCandidate=%v, 期望 %v", c.name, got, c.want)
		}
	}
}

func TestOverBaselineCap(t *testing.T) {
	cases := []struct {
		size  int
		maxKB int
		want  bool
	}{
		{1024, 1, false},           // 恰好 1KB，不超
		{1025, 1, true},            // 超 1KB
		{1024 * 1024, 1024, false}, // 恰好 1MB
		{1024*1024 + 1, 1024, true},
		{500, 0, false}, // maxKB<=0 用默认 1024
	}
	for _, c := range cases {
		if got := overBaselineCap(c.size, c.maxKB); got != c.want {
			t.Errorf("overBaselineCap(%d,%d)=%v, 期望 %v", c.size, c.maxKB, got, c.want)
		}
	}
}

func TestEvaluateTamper(t *testing.T) {
	learned := model.TamperRule{BaselineStatus: 1, BaselineHash: "abc"}
	unlearned := model.TamperRule{BaselineStatus: 0}
	failed := model.TamperRule{BaselineStatus: 2}
	cases := []struct {
		name     string
		liveHash string
		rule     model.TamperRule
		want     tamperDecision
	}{
		{"未学习→捕获", "abc", unlearned, tamperCapture},
		{"已学习哈希一致→放行", "abc", learned, tamperPass},
		{"已学习哈希不一致→篡改", "xyz", learned, tamperTampered},
		{"学习失败→跳过", "abc", failed, tamperSkip},
	}
	for _, c := range cases {
		if got := evaluateTamper(c.liveHash, c.rule); got != c.want {
			t.Errorf("%s: evaluateTamper=%v, 期望 %v", c.name, got, c.want)
		}
	}
}

func TestSha256HexStable(t *testing.T) {
	a := sha256Hex([]byte("hello world"))
	b := sha256Hex([]byte("hello world"))
	c := sha256Hex([]byte("hello world!"))
	if a != b {
		t.Errorf("相同内容哈希应一致: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("不同内容哈希应不同")
	}
	if len(a) != 64 {
		t.Errorf("sha256 十六进制应为64字符，实际 %d", len(a))
	}
}

func TestReadDecompressedBody(t *testing.T) {
	plain := []byte("<html>hello 防篡改</html>")

	// 1) 无压缩
	respPlain := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(bytes.NewReader(plain)),
	}
	got, err := readDecompressedBody(respPlain)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("无压缩读取失败: err=%v got=%q", err, got)
	}
	// 复位后 body 应可再次读取到原始字节
	again, _ := io.ReadAll(respPlain.Body)
	if !bytes.Equal(again, plain) {
		t.Errorf("resp.Body 未正确复位，got=%q", again)
	}

	// 2) gzip 压缩：解压后应与原文一致（哈希基准稳定）
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(plain)
	gw.Close()
	respGzip := &http.Response{
		Header: http.Header{"Content-Encoding": []string{"gzip"}},
		Body:   io.NopCloser(bytes.NewReader(buf.Bytes())),
	}
	gotGzip, err := readDecompressedBody(respGzip)
	if err != nil || !bytes.Equal(gotGzip, plain) {
		t.Fatalf("gzip 解压失败: err=%v got=%q", err, gotGzip)
	}
	// 压缩与不压缩，解压后哈希必须一致
	if sha256Hex(got) != sha256Hex(gotGzip) {
		t.Errorf("同一内容压/不压后哈希应一致")
	}
}

func TestStaticContentType(t *testing.T) {
	// 有扩展名：按扩展名推断（不同机器 mime 表可能有别，只断言非空）
	if ct := staticContentType("/site/index.html", []byte("<html></html>")); ct == "" {
		t.Errorf(".html 应能推断出 Content-Type，实际为空")
	}
	// 无扩展名 + HTML 内容：回退 http.DetectContentType
	if ct := staticContentType("/site/noext", []byte("<html>hi</html>")); !strings.Contains(ct, "text/html") {
		t.Errorf("无扩展名 HTML 内容应回退推断为 text/html，实际 %q", ct)
	}
	// 无扩展名 + 未知二进制：回退为 application/octet-stream
	bin := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	if ct := staticContentType("/site/blob", bin); !strings.Contains(ct, "application/octet-stream") {
		t.Errorf("无扩展名未知内容应回退为 octet-stream，实际 %q", ct)
	}
}

func TestServeStaticTamperBaseline(t *testing.T) {
	waf := &WafEngine{}
	baseline := []byte("<html>correct baseline</html>")
	rule := &model.TamperRule{ContentType: "text/html; charset=utf-8", BaselineContent: baseline}

	// GET：回吐基线正文 + 头部
	getRec := httptest.NewRecorder()
	waf.serveStaticTamperBaseline(getRec, httptest.NewRequest("GET", "/index.html", nil), rule, model.StaticSiteConfig{})
	if getRec.Code != http.StatusOK {
		t.Errorf("状态码应为 200，实际 %d", getRec.Code)
	}
	if !bytes.Equal(getRec.Body.Bytes(), baseline) {
		t.Errorf("GET 应回吐基线正文，实际 %q", getRec.Body.String())
	}
	if ct := getRec.Header().Get("Content-Type"); ct != rule.ContentType {
		t.Errorf("Content-Type 应为 %q，实际 %q", rule.ContentType, ct)
	}
	if cl := getRec.Header().Get("Content-Length"); cl != "29" {
		t.Errorf("Content-Length 应为 29，实际 %q", cl)
	}

	// HEAD：只出头部不出正文
	headRec := httptest.NewRecorder()
	waf.serveStaticTamperBaseline(headRec, httptest.NewRequest("HEAD", "/index.html", nil), rule, model.StaticSiteConfig{})
	if headRec.Body.Len() != 0 {
		t.Errorf("HEAD 不应写正文，实际 %d 字节", headRec.Body.Len())
	}
	if cl := headRec.Header().Get("Content-Length"); cl != "29" {
		t.Errorf("HEAD 仍应带 Content-Length 29，实际 %q", cl)
	}

	// ContentType 为空 → 回退 octet-stream
	emptyRec := httptest.NewRecorder()
	emptyRule := &model.TamperRule{BaselineContent: []byte("x")}
	waf.serveStaticTamperBaseline(emptyRec, httptest.NewRequest("GET", "/x", nil), emptyRule, model.StaticSiteConfig{})
	if ct := emptyRec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("空 ContentType 应回退 octet-stream，实际 %q", ct)
	}
}
