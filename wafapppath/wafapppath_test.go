package wafapppath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowedDirs(t *testing.T) {
	got := ParseAllowedDirs(" /a , ,/b/c ")
	if len(got) != 2 || got[0] != "/a" || got[1] != "/b/c" {
		t.Fatalf("parse explicit=%v", got)
	}
	def := ParseAllowedDirs("")
	if len(def) != 1 || def[0] != DefaultAllowedDir {
		t.Fatalf("parse default=%v", def)
	}
	def = ParseAllowedDirs(" , ")
	if len(def) != 1 || def[0] != DefaultAllowedDir {
		t.Fatalf("parse blank=%v", def)
	}
}

func TestIsSafeCode(t *testing.T) {
	valid := []string{"app-1_ABC", "550e8400-e29b-41d4-a716-446655440000", "a"}
	for _, c := range valid {
		if !IsSafeCode(c) {
			t.Fatalf("code %q should be safe", c)
		}
	}
	invalid := []string{"", "../x", "a/b", `a\b`, "a b", strings.Repeat("a", 65), "a..b", "a.b"}
	for _, c := range invalid {
		if IsSafeCode(c) {
			t.Fatalf("code %q should be unsafe", c)
		}
	}
}

func TestResolveEmptyAppDirUsesDefault(t *testing.T) {
	root := t.TempDir()
	p := Resolve("app1", "", root)
	if !p.Valid || p.Error != "" {
		t.Fatalf("preview=%+v", p)
	}
	want := filepath.Join(root, "app1")
	if p.ResolvedDir != want || p.DefaultDir != want {
		t.Fatalf("resolved=%q default=%q want=%q", p.ResolvedDir, p.DefaultDir, want)
	}
	if p.PathBase != root {
		t.Fatalf("path_base=%q want %q", p.PathBase, root)
	}
	if len(p.AllowedDirs) != 1 || p.AllowedDirs[0] != root {
		t.Fatalf("allowed=%v", p.AllowedDirs)
	}
	// 解析不做任何磁盘写入
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("resolve must not create dir, stat err=%v", err)
	}
}

func TestResolveRelativeAppDirAgainstCwd(t *testing.T) {
	root := t.TempDir()
	p := Resolve("app1", filepath.Join(root, "sub", "..", "app1"), root)
	if !p.Valid {
		t.Fatalf("preview=%+v", p)
	}
	if p.ResolvedDir != filepath.Join(root, "app1") {
		t.Fatalf("resolved=%q", p.ResolvedDir)
	}
}

func TestResolveAbsoluteInsideAllowed(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	p := Resolve("app1", nested, root)
	if !p.Valid || p.ResolvedDir != nested || p.PathBase != root {
		t.Fatalf("preview=%+v", p)
	}
	// 多允许根：命中第二个
	root2 := t.TempDir()
	target := filepath.Join(root2, "x")
	p = Resolve("app1", target, root+","+root2)
	if !p.Valid || p.ResolvedDir != target || p.PathBase != root2 {
		t.Fatalf("preview=%+v", p)
	}
}

func TestResolveOutsideAllowedShowsPath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	p := Resolve("app1", outside, root)
	if p.Valid {
		t.Fatalf("preview should be invalid: %+v", p)
	}
	if p.Error == "" {
		t.Fatal("error message expected")
	}
	abs, _ := filepath.Abs(outside)
	if p.ResolvedDir != abs {
		t.Fatalf("resolved should echo actual path %q got %q", abs, p.ResolvedDir)
	}
	if p.PathBase != "" {
		t.Fatalf("path_base should be empty, got %q", p.PathBase)
	}
	// 越界但同前缀（root 的兄弟目录 root-evil）必须被拒
	sibling := root + "-evil"
	p = Resolve("app1", sibling, root)
	if p.Valid {
		t.Fatalf("sibling prefix must not match: %+v", p)
	}
	// 相对路径逃逸 ../ 必须被拒
	p = Resolve("app1", filepath.Join(root, "sub", "..", "..", "escape"), root)
	if p.Valid {
		t.Fatalf("relative escape must not match: %+v", p)
	}
}

func TestResolveUnsafeCode(t *testing.T) {
	root := t.TempDir()
	p := Resolve("../evil", "", root)
	if p.Valid || p.Error == "" {
		t.Fatalf("preview=%+v", p)
	}
	if _, err := DefaultDir("../evil", root); err == nil {
		t.Fatal("DefaultDir must reject unsafe code")
	}
}

func TestResolveDefaultWhenConfigEmpty(t *testing.T) {
	cwd, _ := os.Getwd()
	p := Resolve("app1", "", "")
	if !p.Valid {
		t.Fatalf("preview=%+v", p)
	}
	want := filepath.Join(cwd, DefaultAllowedDir, "app1")
	if p.ResolvedDir != want {
		t.Fatalf("resolved=%q want %q", p.ResolvedDir, want)
	}
}
