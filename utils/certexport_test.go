package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"SamWaf/global"
)

// 证书导出（issue #929）的路径校验与原子写入用例。
// 收口后（EXT-2026-0821-01）：导出只能落进「内置 data/ssl_export + config 声明目录」，
// 且文件名扩展受白名单约束。拒绝类用例比成功类用例还多。

// setExportBase 把程序目录指到临时目录，并按需设置 config 允许清单，用例结束还原。
func setExportBase(t *testing.T, base, allowedDirs string) {
	t.Helper()
	oldBase := certExportBaseDir
	certExportBaseDir = func() string { return base }
	oldDirs := global.GCONFIG_SSL_EXPORT_ALLOWED_DIRS
	global.GCONFIG_SSL_EXPORT_ALLOWED_DIRS = allowedDirs
	t.Cleanup(func() {
		certExportBaseDir = oldBase
		global.GCONFIG_SSL_EXPORT_ALLOWED_DIRS = oldDirs
	})
}

func TestValidateCertExportPath_拒绝非法输入(t *testing.T) {
	base := filepath.Join(t.TempDir(), "samwaf")
	setExportBase(t, base, "")
	def := filepath.Join(base, "data", "ssl_export") // 内置允许目录，用来构造"目录合法但其它不合法"的用例

	cases := []struct {
		name string
		path string
		kind CertExportKind
	}{
		{"空字符串", "", CertExportCert},
		{"全是空格", "   ", CertExportCert},
		{"含换行", filepath.Join(def, "a\ncert.crt"), CertExportCert},
		{"含NUL", filepath.Join(def, "a\x00cert.crt"), CertExportCert},
		{"相对路径", "certs/a.crt", CertExportCert},
		{"上跳的相对路径", "../a.crt", CertExportCert},
		{"以分隔符结尾", def + string(filepath.Separator), CertExportCert},
		{"证书扩展名不合法", filepath.Join(def, "a.txt"), CertExportCert},
		{"私钥扩展名不合法", filepath.Join(def, "a.crt"), CertExportKey},
		{"无扩展名", filepath.Join(def, "a"), CertExportCert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := ValidateCertExportPath(c.path, c.kind); err == nil {
				t.Fatalf("期望拒绝 %q，实际通过并返回 %q", c.path, got)
			}
		})
	}
}

func TestValidateCertExportPath_内置默认目录被规范化通过(t *testing.T) {
	base := filepath.Join(t.TempDir(), "samwaf")
	setExportBase(t, base, "")
	def := filepath.Join(base, "data", "ssl_export")

	raw := filepath.Join(def, "sub", "..", "a.crt")
	got, err := ValidateCertExportPath("  "+raw+"  ", CertExportCert) // 前后空格应被吃掉
	if err != nil {
		t.Fatalf("内置目录下的合法路径被拒绝: %v", err)
	}
	if want := filepath.Clean(raw); got != want {
		t.Fatalf("规范化结果不对: got=%q want=%q", got, want)
	}
}

// IDE/开发模式下 GetCurrentDir 返回 "."，内置 data/ssl_export 根必须仍生效（相对当前工作目录解析）。
func TestValidateCertExportPath_IDE模式点目录内置根仍生效(t *testing.T) {
	setExportBase(t, ".", "")
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("取当前目录失败: %v", err)
	}
	ok := filepath.Join(cwd, "data", "ssl_export", "a.crt")
	if got, e := ValidateCertExportPath(ok, CertExportCert); e != nil {
		t.Fatalf("开发模式下内置 data/ssl_export 应放行: %s, %v (got=%q)", ok, e, got)
	}
}

func TestValidateCertExportPath_清单外目录被拒(t *testing.T) {
	base := filepath.Join(t.TempDir(), "samwaf")
	setExportBase(t, base, "")

	// 未在允许清单里的绝对目录（含 SamWaf 自身其它目录），一律拒绝
	for _, p := range []string{
		filepath.Join(base, "data", "samwaf_core.db"), // 走后缀会先被扩展名拦，换个 .crt
		filepath.Join(base, "conf", "a.crt"),
		filepath.Join(base, "data", "not_export", "a.crt"),
		filepath.Join(t.TempDir(), "etc", "cron.d", "a.crt"),
	} {
		if _, err := ValidateCertExportPath(p, CertExportCert); err == nil {
			t.Fatalf("清单外路径应被拒绝: %s", p)
		}
	}
}

func TestValidateCertExportPath_config声明目录放行(t *testing.T) {
	base := filepath.Join(t.TempDir(), "samwaf")
	nginxDir := filepath.Join(t.TempDir(), "etc", "nginx", "ssl")
	setExportBase(t, base, nginxDir+" , "+filepath.Join(t.TempDir(), "another")) // 逗号分隔+空格

	// 运营方声明的目录内允许
	for _, tc := range []struct {
		path string
		kind CertExportKind
	}{
		{filepath.Join(nginxDir, "site.crt"), CertExportCert},
		{filepath.Join(nginxDir, "site.key"), CertExportKey},
		{filepath.Join(nginxDir, "site.pem"), CertExportCert},
		{filepath.Join(nginxDir, "sub", "site.crt"), CertExportCert},
	} {
		if _, err := ValidateCertExportPath(tc.path, tc.kind); err != nil {
			t.Fatalf("config 声明目录内应放行: %s, %v", tc.path, err)
		}
	}
	// 声明目录的"前缀相同但其实是别的目录"不能被误放行
	sibling := filepath.Join(t.TempDir(), "etc", "nginx", "ssl_backup", "a.crt")
	if _, err := ValidateCertExportPath(sibling, CertExportCert); err == nil {
		t.Fatalf("前缀相同的兄弟目录不该被放行: %s", sibling)
	}
}

func TestIsSameFilePath(t *testing.T) {
	a := absPath(t, filepath.Join("certs", "a.crt"))
	if !IsSameFilePath(a, filepath.Join(filepath.Dir(a), "sub", "..", "a.crt")) {
		t.Fatal("同一路径的不同写法应判定为相同")
	}
	if IsSameFilePath(a, absPath(t, filepath.Join("certs", "b.crt"))) {
		t.Fatal("不同文件被判定成了相同")
	}
	if IsSameFilePath("", a) || IsSameFilePath(a, "") {
		t.Fatal("空路径不该判定为相同")
	}
	if runtime.GOOS == "windows" {
		if !IsSameFilePath(strings.ToUpper(a), strings.ToLower(a)) {
			t.Fatal("Windows 下应大小写不敏感")
		}
	}
}

func TestWriteCertFileAtomic_新建文件并自动创建目录(t *testing.T) {
	target := filepath.Join(t.TempDir(), "not", "exist", "yet", "a.crt")
	written, err := WriteCertFileAtomic(target, []byte("cert-content"), 0o644)
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if !written {
		t.Fatal("首次写入应返回 written=true")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "cert-content" {
		t.Fatalf("文件内容不对: %q, %v", got, err)
	}
}

func TestWriteCertFileAtomic_内容相同不重写(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a.crt")
	if _, err := WriteCertFileAtomic(target, []byte("same"), 0o644); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}

	written, err := WriteCertFileAtomic(target, []byte("same"), 0o644)
	if err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	if written {
		t.Fatal("内容一致时不应重写（会无谓触发用户侧 reload 脚本）")
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("内容一致时文件修改时间不应变化")
	}
}

func TestWriteCertFileAtomic_覆盖旧内容(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a.crt")
	if _, err := WriteCertFileAtomic(target, []byte("old"), 0o644); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	written, err := WriteCertFileAtomic(target, []byte("new"), 0o644)
	if err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	if !written {
		t.Fatal("内容变化时应重写")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Fatalf("覆盖后内容不对: %q", got)
	}
}

func TestWriteCertFileAtomic_私钥权限0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持 unix 权限位")
	}
	target := filepath.Join(t.TempDir(), "a.key")
	if _, err := WriteCertFileAtomic(target, []byte("key"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限应为 0600，实际 %v", fi.Mode().Perm())
	}
}

func TestWriteCertFileAtomic_拒绝目录(t *testing.T) {
	dir := t.TempDir()
	asDir := filepath.Join(dir, "iamdir")
	if err := os.Mkdir(asDir, 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if _, err := WriteCertFileAtomic(asDir, []byte("x"), 0o644); err == nil {
		t.Fatal("目标是目录时应拒绝")
	}
}

func TestWriteCertFileAtomic_拒绝软链接(t *testing.T) {
	dir := t.TempDir()
	// 跟随软链接会写到别的文件上，是最容易误伤的情况
	realFile := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(realFile, []byte("important"), 0o644); err != nil {
		t.Fatalf("建文件失败: %v", err)
	}
	link := filepath.Join(dir, "link.crt")
	if err := os.Symlink(realFile, link); err != nil {
		t.Skipf("当前环境无法创建软链接（Windows 需要管理员权限）: %v", err)
	}
	if _, err := WriteCertFileAtomic(link, []byte("x"), 0o644); err == nil {
		t.Fatal("目标是软链接时应拒绝")
	}
	got, _ := os.ReadFile(realFile)
	if string(got) != "important" {
		t.Fatalf("软链接指向的原文件被改写了: %q", got)
	}
}

func TestWriteCertFileAtomic_目录不可创建时报错且不留垃圾(t *testing.T) {
	dir := t.TempDir()
	// 拿一个普通文件当"父目录"，MkdirAll 必然失败，用来模拟无权限/路径不可用
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("建文件失败: %v", err)
	}
	target := filepath.Join(blocker, "sub", "a.crt")
	if _, err := WriteCertFileAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("父路径不是目录时应报错")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".samwaf-cert-") {
			t.Fatalf("失败后残留了临时文件: %s", e.Name())
		}
	}
}

func TestWriteCertFileAtomic_写入后目录内无临时文件残留(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.crt")
	if _, err := WriteCertFileAtomic(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "a.crt" {
		t.Fatalf("目录里出现了预期外的文件: %v", entries)
	}
}

// absPath 生成一个跨平台的绝对路径，Windows 下带盘符。
// 这里不能用 filepath.Abs：它在 Windows 上会直接拒绝含控制字符的名字，
// 而含控制字符的路径正是用例要构造的输入。t.TempDir() 本身已经是绝对路径。
func absPath(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if !filepath.IsAbs(dir) {
		t.Fatalf("临时目录不是绝对路径: %s", dir)
	}
	return dir + string(filepath.Separator) + name
}
