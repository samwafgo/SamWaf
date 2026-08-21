package waf_service

import (
	"strings"
	"testing"

	"SamWaf/model/request"
)

// 安全加固回归(EXT-2026-0821-01)：SSL 证书导出任意文件写入。
// 校验 key_content 必须为合法私钥且与证书配对，堵住"任意文本经导出落盘"。

func TestValidateCertKeyPair(t *testing.T) {
	certA, keyA := genExportTestCert(t, "a.example.com")
	_, keyB := genExportTestCert(t, "b.example.com") // 另一对，制造不匹配

	cases := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{"匹配对通过", certA, keyA, false},
		{"私钥严格为空放行(仅存证书不导出)", certA, "", false},
		{"纯空白私钥必须被拒(否则绕过导出空值判定)", certA, "   \n", true},
		{"任意文本被拒", certA, "# PWNED arbitrary content\nnot a key\n", true},
		{"合法但与证书不配对被拒", certA, keyB, true},
		{"伪造PEM私钥块被拒", certA, "-----BEGIN EC PRIVATE KEY-----\nZm9v\n-----END EC PRIVATE KEY-----\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateCertKeyPair(c.cert, c.key)
			if c.wantErr && err == nil {
				t.Fatalf("期望报错，实际通过")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("期望通过，实际报错: %v", err)
			}
		})
	}
}

// TestAddApiRejectsArbitraryKeyContent 证明加固点确实挂在 AddApi 上：
// 合法证书 + 攻击者任意文本 key_content + 恶意导出路径 → 直接被拒，不落库、不落盘。
func TestAddApiRejectsArbitraryKeyContent(t *testing.T) {
	setupSslExportTestDB(t)

	certPEM, _ := genExportTestCert(t, "attack.example.com")
	_, err := WafSslConfigServiceApp.AddApi(request.SslConfigAddReq{
		CertContent:    certPEM,
		KeyContent:     "# PWNED by U-01\narbitrary attacker text\n",
		ExportKeyPath:  "/tmp/should_never_be_written_ext0821.key",
		ExportCertPath: "/tmp/should_never_be_written_ext0821.crt",
	})
	if err == nil {
		t.Fatalf("AddApi 接受了任意文本私钥，加固失效")
	}
	if !strings.Contains(err.Error(), "私钥") {
		t.Fatalf("期望私钥校验类错误，实际: %v", err)
	}
}
