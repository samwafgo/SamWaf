package utils

import (
	"SamWaf/common/zlog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsStaticAssist_ACMEChallenge 复现工单现象：
//
// 站点用「静态网站」模式能签发成功、用反向代理模式必然 404，且请求侧一条日志都没有。
// 怀疑点是 wafengine.go 里 ACME 兜底整段被包在 `if !isStaticAssist {` 内部，
// 后端的 404 只要让 IsStaticAssist 判成"静态资源"，兜底和日志就会被一起吞掉。
//
// 这个用例直接拿真实后端会回的响应头去打 IsStaticAssist，看哪些组合会中招。
func TestIsStaticAssist_ACMEChallenge(t *testing.T) {
	zlog.InitZLog(false, "console")

	// CA 校验时发的请求：无 Accept、无 Sec-Fetch-Dest、路径无扩展名
	newCAReq := func() *http.Request {
		return httptest.NewRequest("GET",
			"http://www.example.com/.well-known/acme-challenge/q1IHnW37smIYQO7piKBIhI7GbxI9BKHPmPbH45_pai4", nil)
	}

	newResp := func(headers map[string]string) *http.Response {
		resp := &http.Response{
			StatusCode: 404,
			Header:     make(http.Header),
			Request:    newCAReq(),
		}
		for k, v := range headers {
			resp.Header.Set(k, v)
		}
		return resp
	}

	cases := []struct {
		name    string
		headers map[string]string
		want    bool
		note    string
	}{
		{
			name:    "nginx默认404",
			headers: map[string]string{"Content-Type": "text/html", "Server": "nginx"},
			want:    false,
			note:    "不中招：兜底生效，所以大部分nginx用户没问题",
		},
		{
			name:    "IIS静态文件处理器404(带Accept-Ranges)",
			headers: map[string]string{"Content-Type": "text/html", "Accept-Ranges": "bytes", "Server": "Microsoft-IIS/10.0"},
			want:    true,
			note:    "中招：整段ACME兜底被跳过",
		},
		{
			name:    "任意后端只要带Accept-Ranges",
			headers: map[string]string{"Content-Type": "text/plain", "Accept-Ranges": "bytes"},
			want:    true,
			note:    "中招",
		},
		{
			name:    "无Content-Type但带Accept-Ranges",
			headers: map[string]string{"Accept-Ranges": "bytes"},
			want:    true,
			note:    "中招",
		},
		{
			name:    "后端把挑战路径当附件下载",
			headers: map[string]string{"Content-Disposition": `attachment; filename="q1IHnW"`},
			want:    true,
			note:    "中招",
		},
		{
			name:    "后端用text/css之类的Content-Type回错误页",
			headers: map[string]string{"Content-Type": "text/css"},
			want:    true,
			note:    "中招",
		},
		{
			name:    "nginx 200 抢答(后端自己有certbot目录)",
			headers: map[string]string{"Content-Type": "text/plain", "Server": "nginx"},
			want:    false,
			note:    "不中招，但会被 sslhttp_check 的状态码白名单挡掉，是另一个工单的原因",
		},

		// ── Apache 2.4（宝塔/phpstudy Windows 面板的默认套件）─────────────
		// Apache 只在响应真正由 default_handler（静态文件处理器）产出时才会加
		// Accept-Ranges: bytes。内部生成的错误页不走 default_handler，
		// 但一旦配了 ErrorDocument 指向一个静态文件，错误页就是子请求走 default_handler 出来的，
		// 这个头就会出现 —— 面板默认给站点配错误页是很常见的。
		{
			name:    "Apache默认404(内部生成错误页)",
			headers: map[string]string{"Content-Type": "text/html; charset=iso-8859-1", "Server": "Apache/2.4.39 (Win64)"},
			want:    false,
			note:    "不中招：兜底应当生效",
		},
		{
			// 工单现场实抓（宝塔 Windows 面板 + Apache 2.4.39，后端在 83 端口）：
			//   curl -I http://127.0.0.1:83/.well-known/acme-challenge/fQsZxrMm2bdux5v0xvzuaCtVNEcNTEtGj4wZY7f_NfI
			//   HTTP/1.1 404 Not Found
			//   Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
			//   Last-Modified / ETag / Accept-Ranges: bytes / Content-Length: 3 / Content-Type: text/html
			// Last-Modified+ETag+Accept-Ranges 这组头说明 404 页是 ErrorDocument 指向的静态文件，
			// 由 default_handler 产出 —— 面板给站点配错误页时就是这个形态。
			name: "★工单实抓：Apache ErrorDocument静态404页",
			headers: map[string]string{
				"Content-Type":  "text/html",
				"Accept-Ranges": "bytes",
				"ETag":          `"3-657b794361eb5"`,
				"Last-Modified": "Wed, 29 Jul 2026 03:30:37 GMT",
				"Server":        "Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02",
			},
			want: true,
			note: "中招：这就是 Windows 那例签不出证书的直接原因",
		},
		{
			name: "Apache命中已存在的静态文件(后端自己放过校验文件)",
			headers: map[string]string{"Content-Type": "text/plain", "Accept-Ranges": "bytes",
				"Server": "Apache/2.4.39 (Win64)"},
			want: true,
			note: "中招：200抢答且连告警都打不出来",
		},
		{
			name: "Apache拒绝以点开头的路径(403)",
			headers: map[string]string{"Content-Type": "text/html; charset=iso-8859-1",
				"Server": "Apache/2.4.39 (Win64)"},
			want: false,
			note: "不中招：会走sslhttp_check的告警分支，日志里应当能看到",
		},
		{
			name: "Apache重写到index.php由PHP吐404页",
			headers: map[string]string{"Content-Type": "text/html; charset=UTF-8",
				"Server": "Apache/2.4.39 (Win64)", "X-Powered-By": "PHP/7.4.3"},
			want: false,
			note: "不中招",
		},
		{
			name: "Apache开了mod_deflate压缩错误页",
			headers: map[string]string{"Content-Type": "text/html; charset=iso-8859-1",
				"Content-Encoding": "gzip", "Server": "Apache/2.4.39 (Win64)", "Vary": "Accept-Encoding"},
			want: false,
			note: "不中招",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := newResp(c.headers)
			got := IsStaticAssist(resp, resp.Header.Get("Content-Type"))
			if got != c.want {
				t.Errorf("IsStaticAssist = %v, 期望 %v（%s）", got, c.want, c.note)
				return
			}
			verdict := "ACME兜底正常执行"
			if got {
				verdict = "★ isStaticAssist=true → ACME兜底整段被跳过，连日志都不打"
			}
			t.Logf("%-46s -> %s", c.name, verdict)
		})
	}
}
