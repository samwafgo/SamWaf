package api

import "testing"

// TestIsValidCaServerAddress 护栏：CA服务器地址必须是可解析的 https URL。
// 反向验证过：把 scheme 判定从 https 改成允许 http 后，http 用例由拒绝变通过、用例变红。
func TestIsValidCaServerAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addr  string
		valid bool
	}{
		{"letsencrypt目录地址", "https://acme-v02.api.letsencrypt.org/directory", true},
		{"内网CA地址", "https://192.168.1.10:8443/acme/directory", true},
		{"带路径内网域名", "https://ca.internal.example/dir", true},
		{"http明文地址", "http://acme.example.com/directory", false},
		{"纯文本", "not-a-url", false},
		{"空串", "", false},
		{"ftp协议", "ftp://acme.example.com/dir", false},
		{"缺少主机", "https://", false},
		{"相对路径", "/acme/directory", false},
		{"带用户信息", "https://user:pass@acme.example.com/dir", false},
		{"端口超范围", "https://acme.example.com:99999/dir", false},
		{"端口非数字", "https://acme.example.com:abc/dir", false},
		{"合法高位端口", "https://acme.example.com:8443/dir", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidCaServerAddress(tc.addr); got != tc.valid {
				t.Fatalf("addr=%q 判定=%v，期望%v", tc.addr, got, tc.valid)
			}
		})
	}
}
