package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Content-Disposition 解析差异绕过危险扩展名拦截：
// SamWaf 解析成 safe.txt 或空串，同一份字节后端却解析成 shell.php

const uploadExtOnlyJSON = `{"is_enable":1,"check_ext":1,"ext_blacklist":"php,htaccess","check_content":0,"check_magic":0,"check_size":0,"max_size_kb":10240,"over_limit_action":"block"}`

// buildRawMultipart 手工拼 multipart，便于构造 Go 的 CreateFormFile 造不出的畸形 Content-Disposition
func buildRawMultipart(contentDisposition string, content []byte) ([]byte, string) {
	const bnd = "SamWafTestBnd"
	var b bytes.Buffer
	b.WriteString("--" + bnd + "\r\n")
	b.WriteString("Content-Disposition: " + contentDisposition + "\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	b.Write(content)
	b.WriteString("\r\n--" + bnd + "--\r\n")
	return b.Bytes(), "multipart/form-data; boundary=" + bnd
}

func checkUploadCD(t *testing.T, cd string) bool {
	t.Helper()
	raw, ct := buildRawMultipart(cd, []byte("harmless"))
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
	r.Header.Set("Content-Type", ct)
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: uploadExtOnlyJSON}}
	return (&WafEngine{}).CheckUpload(r, &innerbean.WebLog{}, url.Values{}, hostTarget, hostTarget).IsBlock
}

func TestCheckUploadFilenameParserDifferential(t *testing.T) {
	cases := []struct {
		name string
		cd   string
		want bool
	}{
		{"普通危险扩展名", `form-data; name="file"; filename="shell.php"`, true},
		{"UTF-8扩展参数", `form-data; name="file"; filename*=UTF-8''shell.php`, true},
		{"benign回退+UTF-8", `form-data; name="file"; filename="safe.txt"; filename*=UTF-8''shell.php`, true},
		{"benign回退+UTF-7", `form-data; name="file"; filename="safe.txt"; filename*=UTF-7''shell.php`, true},
		{"benign回退+ISO-8859-1", `form-data; name="file"; filename="safe.txt"; filename*=ISO-8859-1''shell.php`, true},
		{"benign回退+未知字符集", `form-data; name="file"; filename="safe.txt"; filename*=X-UNKNOWN''shell.php`, true},
		{"仅UTF-7扩展参数", `form-data; name="file"; filename*=UTF-7''shell.php`, true},
		{"仅ISO-8859-1扩展参数", `form-data; name="file"; filename*=ISO-8859-1''shell.php`, true},
		{"仅未知字符集扩展参数", `form-data; name="file"; filename*=X-UNKNOWN''shell.php`, true},
		{"重复filename参数", `form-data; name="file"; filename="safe.txt"; filename="shell.php"`, true},
		{"重复filename参数-逆序", `form-data; name="file"; filename="shell.php"; filename="safe.txt"`, true},
		{"RFC2231分段拼接", `form-data; name="file"; filename*0*=UTF-8''sh; filename*1*=ell.php`, true},
		{"未知字符集分段拼接", `form-data; name="file"; filename*0*=X-UNKNOWN''sh; filename*1*=ell.php`, true},
		{"百分号编码点号", `form-data; name="file"; filename*=UTF-8''shell%2Ephp`, true},
		{"引号转义", `form-data; name="file"; filename="shell\".php"`, true},

		// 反例：正常上传与普通表单字段不能被误拦
		{"正常文件", `form-data; name="file"; filename="safe.txt"`, false},
		{"正常图片", `form-data; name="file"; filename="photo.jpg"`, false},
		{"UTF-8正常文件名", `form-data; name="file"; filename*=UTF-8''%E6%8A%A5%E5%91%8A.txt`, false},
		{"benign回退+benign扩展参数", `form-data; name="file"; filename="safe.txt"; filename*=ISO-8859-1''report.txt`, false},
		{"非文件表单字段", `form-data; name="username"`, false},
		{"字段值里含filename字样", `form-data; name="filename"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checkUploadCD(t, c.cd); got != c.want {
				t.Errorf("CD=%q 期望拦截=%v 实际=%v", c.cd, c.want, got)
			}
		})
	}
}

// 畸形 part 曾让扫描循环提前 break，后续 part 里的 shell.php 完全不过检
func TestCheckUploadMalformedPartFailsClosed(t *testing.T) {
	const bnd = "SamWafTestBnd"
	var b bytes.Buffer
	b.WriteString("--" + bnd + "\r\nContent-Disposition: form-data; name=\"a\"; filename=\"ok.txt\"\r\n\r\nA\r\n")
	b.WriteString("--" + bnd + "\r\nBadHeaderWithoutColon\r\n\r\nB\r\n")
	b.WriteString("--" + bnd + "\r\nContent-Disposition: form-data; name=\"c\"; filename=\"shell.php\"\r\n\r\nC\r\n")
	b.WriteString("--" + bnd + "--\r\n")

	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(b.Bytes()))
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+bnd)
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: uploadExtOnlyJSON}}
	res := (&WafEngine{}).CheckUpload(r, &innerbean.WebLog{}, url.Values{}, hostTarget, hostTarget)
	if !res.IsBlock {
		t.Errorf("畸形 multipart 报文应 fail-closed 拦截，实际放行 %+v", res)
	}
}

func TestUploadPartFileNamesCoversBackendCandidates(t *testing.T) {
	cases := []struct {
		cd   string
		want string
	}{
		{`form-data; name="file"; filename="safe.txt"; filename*=ISO-8859-1''shell.php`, "shell.php"},
		{`form-data; name="file"; filename*=X-UNKNOWN''shell.php`, "shell.php"},
		{`form-data; name="file"; filename="safe.txt"; filename="shell.php"`, "shell.php"},
	}
	for _, c := range cases {
		raw, ct := buildRawMultipart(c.cd, []byte("x"))
		r := httptest.NewRequest("POST", "/upload", bytes.NewReader(raw))
		r.Header.Set("Content-Type", ct)
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatalf("MultipartReader: %v", err)
		}
		part, err := mr.NextRawPart()
		if err != nil {
			t.Fatalf("NextRawPart: %v", err)
		}
		names := uploadPartFileNames(part)
		found := false
		for _, n := range names {
			if n == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("CD=%q 候选 %v 未包含后端会解析出的 %q", c.cd, names, c.want)
		}
	}
}

// Content-Disposition 头重复出现：Go 只取第一条，后端可能取最后一条
func TestCheckUploadDuplicateDispositionHeader(t *testing.T) {
	const bnd = "SamWafTestBnd"
	var b bytes.Buffer
	b.WriteString("--" + bnd + "\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n")
	b.WriteString("harmless\r\n--" + bnd + "--\r\n")

	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(b.Bytes()))
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+bnd)
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{UploadSecurityJSON: uploadExtOnlyJSON}}
	res := (&WafEngine{}).CheckUpload(r, &innerbean.WebLog{}, url.Values{}, hostTarget, hostTarget)
	if !res.IsBlock {
		t.Errorf("重复 Content-Disposition 头携带 shell.php 应被拦截，实际放行 %+v", res)
	}
}
