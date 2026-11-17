package ssl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestWebrootProvider 在临时目录下构造 provider。
func newTestWebrootProvider(t *testing.T) (*loggingWebrootProvider, string) {
	t.Helper()
	root := t.TempDir()
	p, err := newLoggingWebrootProvider(root, "host_test")
	if err != nil {
		t.Fatalf("构造provider失败: %v", err)
	}
	return p, root
}

// TestResolveChallengeFilePath 护栏：token 字符集约束 + 最终路径目录锚定。
// 反向验证过：把 challengeTokenPattern 放开为全匹配后，越界用例全部变绿（护栏变红）。
func TestResolveChallengeFilePath(t *testing.T) {
	p, root := newTestWebrootProvider(t)

	longToken := strings.Repeat("a", 256)
	boundaryOK := strings.Repeat("b", 255)
	for _, tc := range []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"合法token", "abcDEF-_123", false},
		{"边界255字符", boundaryOK, false},
		{"点号穿越", "../../evil", true},
		{"反斜杠穿越", `..\..\evil`, true},
		{"绝对路径", "/etc/evil", true},
		{"盘符路径", `C:\evil`, true},
		{"含斜杠", "ab/cd", true},
		{"含换行", "abc\ndef", true},
		{"空token", "", true},
		{"超长token", longToken, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, err := p.resolveChallengeFilePath(tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("token=%q 应当被拒绝，得到路径=%s", tc.token, path)
				}
				return
			}
			if err != nil {
				t.Fatalf("token=%q 应当通过，错误=%v", tc.token, err)
			}
			// 通过的路径必须落在 root 之内
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				t.Fatalf("路径=%s 逃出root=%s", path, root)
			}
			if !strings.HasPrefix(path, filepath.Clean(root)) {
				t.Fatalf("路径=%s 不在root=%s 内", path, root)
			}
		})
	}
}

// TestPresentRejectsInvalidToken 护栏：非法 token 直接返回错误，不写盘、不登记。
// token 用三层".."（挑战路径本身占两层）确保逃出 root 落到其父目录。
// 反向验证过：把 challengeTokenPattern 放开、目录锚定摘除后，越界文件被写出、用例变红。
func TestPresentRejectsInvalidToken(t *testing.T) {
	p, root := newTestWebrootProvider(t)
	outside := filepath.Join(filepath.Dir(root), "acme_present_guard.txt")

	if err := p.Present("xxxx.com", "../../../acme_present_guard", "keyAuth"); err == nil {
		t.Fatal("非法token的Present应当返回错误")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatalf("越界文件被写出: %s", outside)
	}
	// root 内也不应有任何残留
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("root内出现意料之外的文件: %d个", len(entries))
	}
}

// TestCleanUpInvalidTokenKeepsOutsideFile 护栏：CleanUp 对非法 token 不做任何磁盘操作。
// token 用三层".."（挑战路径本身占两层）确保目标逃出 root 落在其父目录的哨兵文件上。
// 反向验证过：把 challengeTokenPattern 放开、目录锚定摘除后，root 之外的哨兵文件会被删除、用例变红。
func TestCleanUpInvalidTokenKeepsOutsideFile(t *testing.T) {
	p, root := newTestWebrootProvider(t)
	outside := filepath.Join(filepath.Dir(root), "acme_cleanup_guard.txt")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	if err := p.CleanUp("xxxx.com", `..\..\..\acme_cleanup_guard.txt`, "keyAuth"); err == nil {
		t.Fatal("非法token的CleanUp应当返回错误")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("root之外的文件被误删: %s", outside)
	}
}

// TestPresentCleanUpRoundTrip 合法 token 全流程：写盘可回读，清理后文件消失。
func TestPresentCleanUpRoundTrip(t *testing.T) {
	p, _ := newTestWebrootProvider(t)
	token := "legalToken_123-abc"
	keyAuth := "keyAuthValue"

	if err := p.Present("xxxx.com", token, keyAuth); err != nil {
		t.Fatalf("Present失败: %v", err)
	}
	path, err := p.resolveChallengeFilePath(token)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("挑战文件不可回读: %v", err)
	}
	if string(data) != keyAuth {
		t.Fatalf("挑战文件内容=%q 期望=%q", data, keyAuth)
	}

	if err := p.CleanUp("xxxx.com", token, keyAuth); err != nil {
		t.Fatalf("CleanUp失败: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("挑战文件清理后仍存在: %v", err)
	}
}
