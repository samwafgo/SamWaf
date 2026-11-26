package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// 静态目录内的文件若是 config.yml 自定义的密钥文件，按真实路径拒绝伺服；同目录的普通文件照常。
func TestServeStaticFileDeniesProtectedFile(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("ok.txt", "ok")
	keyFile := write("key.txt", "secret")
	write("sub/index.html", "sub")
	write("index.html", "home")

	origData := global.GCONFIG_DATA_KEY_FILE
	t.Cleanup(func() { global.GCONFIG_DATA_KEY_FILE = origData })

	cfg := InitDefaultStaticSiteConfig()
	cfg.IsEnableStaticSite = 1
	cfg.StaticSitePath = root
	waf := &WafEngine{}
	serve := func(path string, c model.StaticSiteConfig) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		waf.serveStaticFile(rec, req, c, &innerbean.WebLog{}, &wafenginmodel.HostSafe{})
		return rec
	}

	global.GCONFIG_DATA_KEY_FILE = keyFile
	if rec := serve("/key.txt", cfg); rec.Code != http.StatusForbidden {
		t.Fatalf("key file: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec := serve("/ok.txt", cfg); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("normal file: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// 目录首页与 SPA 回退页同样受保护
	global.GCONFIG_DATA_KEY_FILE = filepath.Join(root, "sub", "index.html")
	if rec := serve("/sub/", cfg); rec.Code != http.StatusForbidden {
		t.Fatalf("dir index: code=%d", rec.Code)
	}
	global.GCONFIG_DATA_KEY_FILE = filepath.Join(root, "index.html")
	spa := cfg
	spa.SpaFallback = 1
	if rec := serve("/no/such/page", spa); rec.Code != http.StatusForbidden {
		t.Fatalf("spa fallback: code=%d", rec.Code)
	}
	global.GCONFIG_DATA_KEY_FILE = keyFile
	if rec := serve("/no/such/page", spa); rec.Code != http.StatusOK || rec.Body.String() != "home" {
		t.Fatalf("spa fallback normal: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// makeStaticTestLink 创建指向 target 的目录链接：优先软链接，Windows 上退到 junction。
func makeStaticTestLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err == nil {
			return
		} else {
			t.Skipf("目录链接不可用: %v %s", err, out)
		}
	}
	t.Skipf("本机不支持创建目录链接")
}

// 静态根目录保存后才出现指向受保护位置的链接时，运行时仍按真实路径拒绝伺服。
func TestServeStaticFileDeniesLinkCreatedAfterSave(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	protectedDir := t.TempDir()
	keyFile := filepath.Join(protectedDir, "key.txt")
	if err := os.WriteFile(keyFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	origData := global.GCONFIG_DATA_KEY_FILE
	t.Cleanup(func() { global.GCONFIG_DATA_KEY_FILE = origData })
	global.GCONFIG_DATA_KEY_FILE = keyFile

	cfg := InitDefaultStaticSiteConfig()
	cfg.IsEnableStaticSite = 1
	cfg.StaticSitePath = root

	// 站点配置已保存，链接随后出现在根目录内
	makeStaticTestLink(t, protectedDir, filepath.Join(root, "evil"))
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "page.html"), []byte("page"), 0o644); err != nil {
		t.Fatal(err)
	}
	makeStaticTestLink(t, plain, filepath.Join(root, "fine"))

	waf := &WafEngine{}
	serve := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		waf.serveStaticFile(rec, httptest.NewRequest(http.MethodGet, p, nil), cfg, &innerbean.WebLog{}, &wafenginmodel.HostSafe{})
		return rec
	}

	if rec := serve("/evil/key.txt"); rec.Code != http.StatusForbidden {
		t.Fatalf("file through link to protected target: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec := serve("/fine/page.html"); rec.Code != http.StatusOK || rec.Body.String() != "page" {
		t.Fatalf("file through ordinary link: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec := serve("/ok.txt"); rec.Code != http.StatusOK {
		t.Fatalf("plain file: code=%d", rec.Code)
	}
	if rec := serve("/missing.txt"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing file must stay 404: code=%d", rec.Code)
	}
}
