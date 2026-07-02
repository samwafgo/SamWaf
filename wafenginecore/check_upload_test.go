package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestMatchDangerousExt(t *testing.T) {
	cases := []struct {
		name string
		file string
		want bool
	}{
		{"php", "shell.php", true},
		{"大写php", "shell.PHP", true},
		{"双扩展名", "shell.php.jpg", true},      // Apache 误配会执行 .php
		{"空字节绕过", "shell.php\x00.jpg", true}, // 空字节截断后 shell.php
		{"jsp", "a.jsp", true},
		{"正常图片", "photo.jpg", false},
		{"正常png", "logo.png", false},
		{"正常pdf", "doc.pdf", false},
		{"无扩展名", "README", false},
	}
	for _, c := range cases {
		if bad, _ := matchDangerousExt(c.file, ""); bad != c.want {
			t.Errorf("%s: matchDangerousExt(%q)=%v, 期望 %v", c.name, c.file, bad, c.want)
		}
	}
}

func TestScanWebshell(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"php一句话", "<?php @eval($_POST['x']);?>", true},
		{"php assert", "<?php assert($_REQUEST['a']);", true},
		{"php标记+system", "<?php system($cmd); ?>", true},
		{"jsp exec", "<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>", true},
		{"asp eval", "<%eval request(\"cmd\")%>", true},
		{"压缩JS含eval不误报", "!function(){var a=eval('1+1');return a}()", false},
		{"正常HTML", "<html><body><h1>hello</h1></body></html>", false},
		{"正常文本", "just some plain text content", false},
	}
	for _, c := range cases {
		if hit, _ := scanWebshell([]byte(c.body)); hit != c.want {
			t.Errorf("%s: scanWebshell=%v, 期望 %v", c.name, hit, c.want)
		}
	}
}

func TestIsUploadTypeMismatch(t *testing.T) {
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	php := []byte("<?php eval($_POST['x']); ?>")
	html := []byte("<html><script>alert(1)</script></html>")

	if isUploadTypeMismatch("photo.jpg", "image/jpeg", jpeg) {
		t.Errorf("真 JPEG 声称图片不应判不符")
	}
	if !isUploadTypeMismatch("photo.jpg", "image/jpeg", php) {
		t.Errorf("声称 jpg 实为 php 应判不符")
	}
	if !isUploadTypeMismatch("avatar.png", "image/png", html) {
		t.Errorf("声称 png 实为 html 应判不符")
	}
	if isUploadTypeMismatch("script.js", "application/javascript", php) {
		t.Errorf("非图片声明不做类型不符判定（避免误报），应放行")
	}
}

func TestOverUploadSizeAndPathPrefix(t *testing.T) {
	if overUploadSize(1024, 1) {
		t.Errorf("恰好 1KB 不应超")
	}
	if !overUploadSize(2049, 2) {
		t.Errorf("2049>2KB 应超")
	}
	if !matchUploadPathPrefix("/api/upload/x", "/api/upload\n/img") {
		t.Errorf("应命中前缀")
	}
	if matchUploadPathPrefix("/other", "/api/upload\n/img") {
		t.Errorf("不应命中")
	}
}

// buildMultipart 构造一个含单个文件 part 的 multipart body
func buildMultipart(t *testing.T, field, filename, contentType string, content []byte) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write(content)
	w.Close()
	return &buf, w.FormDataContentType()
}

const uploadEnabledJSON = `{"is_enable":1,"check_ext":1,"check_content":1,"check_magic":1,"check_size":1,"max_size_kb":10240,"over_limit_action":"block"}`

func TestCheckUploadBlocksAndResetsBody(t *testing.T) {
	waf := &WafEngine{}
	buf, ct := buildMultipart(t, "file", "shell.php", "application/octet-stream", []byte("<?php @eval($_POST['x']);"))
	raw := buf.Bytes()
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	weblog := &innerbean.WebLog{}
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: uploadEnabledJSON}}

	res := waf.CheckUpload(r, weblog, url.Values{}, hostTarget, hostTarget)
	if !res.IsBlock {
		t.Fatalf("恶意 .php 上传应被拦截，实际 %+v", res)
	}
	// 关键：r.Body 必须已复位为完整原始字节（否则代理转发丢包）
	after, _ := io.ReadAll(r.Body)
	if !bytes.Equal(after, raw) {
		t.Errorf("CheckUpload 后 r.Body 未复位为完整原始 body（转发会丢包）")
	}
}

func TestCheckUploadCleanPasses(t *testing.T) {
	waf := &WafEngine{}
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01}
	buf, ct := buildMultipart(t, "file", "photo.jpg", "image/jpeg", jpeg)
	raw := buf.Bytes()
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	weblog := &innerbean.WebLog{}
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: uploadEnabledJSON}}

	res := waf.CheckUpload(r, weblog, url.Values{}, hostTarget, hostTarget)
	if res.IsBlock {
		t.Errorf("正常图片上传不应拦截，实际 %+v", res)
	}
	after, _ := io.ReadAll(r.Body)
	if !bytes.Equal(after, raw) {
		t.Errorf("正常上传 r.Body 应完整复位")
	}
}

func TestCheckUploadDisabledSkips(t *testing.T) {
	waf := &WafEngine{}
	buf, ct := buildMultipart(t, "file", "shell.php", "application/octet-stream", []byte("<?php eval($_POST[0]);"))
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(buf.Bytes()))
	r.Header.Set("Content-Type", ct)
	weblog := &innerbean.WebLog{}
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: ""}} // 未开启
	res := waf.CheckUpload(r, weblog, url.Values{}, hostTarget, hostTarget)
	if res.IsBlock {
		t.Errorf("未开启文件上传检测不应拦截")
	}
}
