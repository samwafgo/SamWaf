package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"SamWaf/global"
)

func withStaticSiteBase(t *testing.T, allowed string) string {
	t.Helper()
	base := t.TempDir()
	origBase, origAllowed := staticSiteBaseDir, global.GCONFIG_STATIC_SITE_ALLOWED_DIRS
	origData, origComm := global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE
	staticSiteBaseDir = func() string { return base }
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = allowed
	global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = "", ""
	t.Cleanup(func() {
		staticSiteBaseDir, global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = origBase, origAllowed
		global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = origData, origComm
		staticProtectedCache.Store(nil)
	})
	staticProtectedCache.Store(nil)
	return base
}

// makeStaticDirLink 创建指向 target 的目录链接：优先软链接，Windows 上退到 junction。
func makeStaticDirLink(t *testing.T, target, link string) {
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

// windowsShortPath 取路径的 8.3 短名，不可用时返回空串。
func windowsShortPath(t *testing.T, p string) string {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "for", "%I", "in", "("+p+")", "do", "@echo", "%~sI").Output()
	if err != nil {
		return ""
	}
	short := strings.TrimSpace(string(out))
	if short == "" || strings.EqualFold(short, p) {
		return ""
	}
	return short
}

func TestValidateStaticRoot(t *testing.T) {
	extra := t.TempDir()
	base := withStaticSiteBase(t, extra)
	cases := []struct {
		name string
		raw  string
		code string
	}{
		{"empty", "  ", StaticRootInvalid},
		{"relative", "www", StaticRootInvalid},
		{"newline", extra + "\nx", StaticRootInvalid},
		{"default dir", filepath.Join(base, "data", "static_site"), ""},
		{"default subdir", filepath.Join(base, "data", "static_site", "site1"), ""},
		{"allowed dir", extra, ""},
		{"allowed subdir", filepath.Join(extra, "a", "b"), ""},
		{"dotdot escape", filepath.Join(extra, "a") + string(filepath.Separator) + ".." + string(filepath.Separator) + "..", StaticRootNotAllowed},
		{"sibling prefix", extra + "2", StaticRootNotAllowed},
		{"program dir", base, StaticRootNotAllowed},
		{"data dir", filepath.Join(base, "data"), StaticRootProtected},
		{"data subdir", filepath.Join(base, "data", "x"), StaticRootProtected},
		{"conf dir", filepath.Join(base, "conf"), StaticRootProtected},
		{"default via dotdot to data", filepath.Join(base, "data", "static_site", ".."), StaticRootProtected},
		{"drive relative", "C:foo", StaticRootInvalid},
		{"device prefix", `\\?\C:\x\y`, StaticRootInvalid},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateStaticRoot(tt.raw)
			if got := StaticRootErrorCode(err); got != tt.code {
				t.Fatalf("code=%q want=%q err=%v", got, tt.code, err)
			}
		})
	}
}

func TestValidateStaticRootProtectedEvenIfAllowed(t *testing.T) {
	base := t.TempDir()
	withStaticSiteBaseAt(t, base, base)
	if _, err := ValidateStaticRoot(base); err != nil {
		t.Fatalf("program dir declared by operator should pass: %v", err)
	}
	if _, err := ValidateStaticRoot(filepath.Join(base, "data")); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("data dir must stay protected: %v", err)
	}
}

func withStaticSiteBaseAt(t *testing.T, base, allowed string) {
	t.Helper()
	origBase, origAllowed := staticSiteBaseDir, global.GCONFIG_STATIC_SITE_ALLOWED_DIRS
	origData, origComm := global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE
	staticSiteBaseDir = func() string { return base }
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = allowed
	global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = "", ""
	t.Cleanup(func() {
		staticSiteBaseDir, global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = origBase, origAllowed
		global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = origData, origComm
		staticProtectedCache.Store(nil)
	})
	staticProtectedCache.Store(nil)
}

func TestValidateStaticRootSymlink(t *testing.T) {
	extra := t.TempDir()
	base := withStaticSiteBase(t, extra)
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(extra, "link")
	if err := os.Symlink(dataDir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ValidateStaticRoot(link); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("symlink into data dir: %v", err)
	}
	outside := t.TempDir()
	link2 := filepath.Join(extra, "link2")
	if err := os.Symlink(outside, link2); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := ValidateStaticRoot(link2); StaticRootErrorCode(err) != StaticRootNotAllowed {
		t.Fatalf("symlink out of allowed dirs: %v", err)
	}
}

func TestIsProtectedStaticFile(t *testing.T) {
	base := withStaticSiteBase(t, "")
	keyFile := filepath.Join(t.TempDir(), "dek")
	global.GCONFIG_DATA_KEY_FILE = keyFile
	cases := []struct {
		p    string
		want bool
	}{
		{filepath.Join(base, "data", "local.db"), true},
		{filepath.Join(base, "conf", "config.yml"), true},
		{filepath.Join(base, "data", "static_site", "index.html"), false},
		{filepath.Join(base, "www", "index.html"), false},
		{filepath.Join(base, "dataset", "a.txt"), false},
		{keyFile, true},
	}
	for _, tt := range cases {
		if got := IsProtectedStaticFile(tt.p); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.p, got, tt.want)
		}
	}
}

// data 目录本身是链接（容器卷）时，默认静态目录、受保护目录与运行时判定都按真实路径识别。
func TestStaticProtectionDataDirIsLink(t *testing.T) {
	realData := t.TempDir()
	base := withStaticSiteBase(t, "")
	link := filepath.Join(base, "data")
	if err := os.MkdirAll(filepath.Join(realData, "static_site"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(filepath.Join(realData, "local.db"), "secret")
	writeFile(filepath.Join(realData, "static_site", "index.html"), "home")

	makeStaticDirLink(t, realData, link)

	if _, err := ValidateStaticRoot(filepath.Join(link, "static_site")); err != nil {
		t.Fatalf("default dir through data link should pass: %v", err)
	}
	if _, err := ValidateStaticRoot(link); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("data link itself must stay protected: %v", err)
	}
	if !IsProtectedStaticFile(filepath.Join(link, "local.db")) {
		t.Fatal("file through data link must be protected")
	}
	if !IsProtectedStaticFile(filepath.Join(realData, "local.db")) {
		t.Fatal("file at link target must be protected")
	}
	if IsProtectedStaticFile(filepath.Join(link, "static_site", "new.txt")) {
		t.Fatal("missing file under default dir must not be protected")
	}
}

// 保存后才在允许目录内出现的链接，运行时判定仍按真实路径拦截。
func TestIsProtectedStaticFileLinkInsideAllowedRoot(t *testing.T) {
	base := withStaticSiteBase(t, "")
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "local.db"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := t.TempDir()
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = extra

	evil := filepath.Join(extra, "evil")
	makeStaticDirLink(t, dataDir, evil)
	if !IsProtectedStaticFile(filepath.Join(evil, "local.db")) {
		t.Fatal("file through link into data must be protected")
	}
	if !IsProtectedStaticFile(filepath.Join(evil, "new.db")) {
		t.Fatal("missing file through link into data must be protected")
	}

	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(extra, "good")
	makeStaticDirLink(t, plain, good)
	if IsProtectedStaticFile(filepath.Join(good, "ok.txt")) {
		t.Fatal("file through link to ordinary dir must stay servable")
	}
}

// 程序目录自身是链接时，受保护目录与内置默认目录仍按真实路径识别。
func TestStaticProtectionProgramDirIsLink(t *testing.T) {
	realBase := t.TempDir()
	linkBase := filepath.Join(t.TempDir(), "program")
	if err := os.MkdirAll(filepath.Join(realBase, "data", "static_site"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(realBase, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realBase, "data", "local.db"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	makeStaticDirLink(t, realBase, linkBase)

	withStaticSiteBaseAt(t, linkBase, "")
	if _, err := ValidateStaticRoot(filepath.Join(linkBase, "data")); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("data dir through program link must stay protected: %v", err)
	}
	if _, err := ValidateStaticRoot(filepath.Join(linkBase, "data", "static_site")); err != nil {
		t.Fatalf("default dir through program link should pass: %v", err)
	}
	if !IsProtectedStaticFile(filepath.Join(realBase, "data", "local.db")) {
		t.Fatal("file at real program data must be protected")
	}
	if !IsProtectedStaticFile(filepath.Join(linkBase, "data", "local.db")) {
		t.Fatal("file at linked program data must be protected")
	}
	if !IsProtectedStaticFile(filepath.Join(linkBase, "conf", "config.yml")) {
		t.Fatal("file at linked program conf must be protected")
	}
	if IsProtectedStaticFile(filepath.Join(linkBase, "data", "static_site", "index.html")) {
		t.Fatal("default static file must stay servable")
	}
}

// 链接链无法解析（跳数用尽）时按受保护处理，不因解析失败放行。
func TestIsProtectedStaticFileFailClosed(t *testing.T) {
	base := withStaticSiteBase(t, "")
	extra := t.TempDir()
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = extra
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	plain := t.TempDir()
	link := filepath.Join(extra, "j")
	makeStaticDirLink(t, plain, link)

	target := filepath.Join(link, "nope.txt")
	if IsProtectedStaticFile(target) {
		t.Fatal("ordinary link should not be protected")
	}

	orig := staticMaxLinkHops
	staticMaxLinkHops = 0
	t.Cleanup(func() { staticMaxLinkHops = orig })
	if !IsProtectedStaticFile(target) {
		t.Fatal("unresolvable link chain must be treated as protected")
	}
}

// 程序目录由相对路径给出（SamWafIDE 环境变量下 GetCurrentDir 返回 "."）时仍能判定。
func TestStaticProtectionRelativeProgramDir(t *testing.T) {
	origBase := staticSiteBaseDir
	origAllowed := global.GCONFIG_STATIC_SITE_ALLOWED_DIRS
	origData, origComm := global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE
	staticSiteBaseDir = func() string { return "." }
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = ""
	global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = "", ""
	t.Cleanup(func() {
		staticSiteBaseDir = origBase
		global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = origAllowed
		global.GCONFIG_DATA_KEY_FILE, global.GCONFIG_COMM_KEY_FILE = origData, origComm
		staticProtectedCache.Store(nil)
	})
	staticProtectedCache.Store(nil)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateStaticRoot(StaticSiteDefaultDir()); err != nil {
		t.Fatalf("default dir under relative program dir should pass: %v", err)
	}
	if _, err := ValidateStaticRoot(filepath.Join(cwd, "data")); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("data dir under relative program dir must be protected: %v", err)
	}
	if _, err := ValidateStaticRoot(filepath.Join(cwd, "conf")); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("conf dir under relative program dir must be protected: %v", err)
	}
}

func TestValidateStaticRootWindowsForms(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专属路径形式")
	}
	base := withStaticSiteBase(t, "")
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "data", "local.db"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 尾点与尾空格：NTFS 打开时忽略，按真实路径仍判为受保护目录
	for _, raw := range []string{filepath.Join(base, "data") + ".", filepath.Join(base, "data") + " "} {
		if _, err := ValidateStaticRoot(raw); StaticRootErrorCode(err) != StaticRootProtected {
			t.Fatalf("%q should be protected: %v", raw, err)
		}
	}
	if !IsProtectedStaticFile(filepath.Join(base, "data") + string(filepath.Separator) + "local.db") {
		t.Fatal("file in data dir must be protected")
	}

	// 大小写不敏感
	if _, err := ValidateStaticRoot(strings.ToUpper(filepath.Join(base, "data"))); StaticRootErrorCode(err) != StaticRootProtected {
		t.Fatalf("upper-cased data dir should be protected: %v", err)
	}

	// UNC 路径是绝对路径，但不在允许目录内
	if _, err := ValidateStaticRoot(`\\server\share\www`); StaticRootErrorCode(err) != StaticRootNotAllowed {
		t.Fatalf("unc path should be not allowed: %v", err)
	}

	// 8.3 短名：运行时按真实路径识别；未声明的短名目录在保存时按不在允许目录内拒绝
	if short := windowsShortPath(t, base); short != "" {
		if !IsProtectedStaticFile(filepath.Join(short, "data", "local.db")) {
			t.Fatal("8.3 short path file must be protected")
		}
		if _, err := ValidateStaticRoot(filepath.Join(short, "data")); StaticRootErrorCode(err) != StaticRootNotAllowed {
			t.Fatalf("undeclared 8.3 short dir should be rejected: %v", err)
		}
		// 程序目录本身以短名给出时，内置默认目录与受保护目录都能判定
		withStaticSiteBaseAt(t, short, "")
		if _, err := ValidateStaticRoot(StaticSiteDefaultDir()); err != nil {
			t.Fatalf("default dir under short program dir should pass: %v", err)
		}
		if _, err := ValidateStaticRoot(filepath.Join(short, "data")); StaticRootErrorCode(err) != StaticRootProtected {
			t.Fatalf("short data dir under short program dir must be protected: %v", err)
		}
	}
}

func TestSameStaticRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		if !SameStaticRoot(`C:\www\site.`, `C:\WWW\SITE`) {
			t.Fatal("trailing dot and case should compare equal on Windows")
		}
	}
	if !SameStaticRoot("/var/www/a", "/var/www/a") {
		t.Fatal("identical paths should compare equal")
	}
	if SameStaticRoot("", "/var/www") {
		t.Fatal("empty and non-empty must differ")
	}
}

// 内置默认目录被换成指向 conf/data 的软链接时，不能因此成为允许根或豁免受保护目录。
func TestDefaultDirSymlinkCannotEscape(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	def := filepath.Join(base, "data", "static_site")
	if err := os.Symlink(filepath.Join(base, "conf"), def); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	withStaticSiteBaseAt(t, base, "")
	if _, err := ValidateStaticRoot(def); StaticRootErrorCode(err) == "" {
		t.Fatalf("default dir linked to conf must be rejected: %v", err)
	}
	if _, err := ValidateStaticRoot(filepath.Join(def, "config.yml")); StaticRootErrorCode(err) == "" {
		t.Fatalf("file under linked default dir must be rejected")
	}
	if !IsProtectedStaticFile(filepath.Join(def, "config.yml")) {
		t.Fatal("file served through linked default dir must stay protected")
	}
}
