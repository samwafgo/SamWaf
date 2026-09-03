package wafinit

import (
	"embed"
	"os"
	"path/filepath"
	"testing"
)

//go:embed testdata/pack
var testPack embed.FS

// 用户改过的文件在下一次释放时必须原样保留，新版本另存为 .new。
// 升级是无人值守的，静默覆盖等于把别人的定制在夜里抹掉。
func TestReleaseFiles_KeepsUserModifiedFile(t *testing.T) {
	dir := t.TempDir()

	// 第一次释放：目录是空的，正常写入并记下指纹
	if err := ReleaseFiles(testPack, "testdata/pack", dir, "pack"); err != nil {
		t.Fatalf("首次释放失败: %v", err)
	}
	target := filepath.Join(dir, "index.html")
	if _, err := os.Stat(filepath.Join(dir, releaseManifestName)); err != nil {
		t.Fatalf("首次释放后应写下释放记录: %v", err)
	}

	// 用户改了这个文件
	custom := []byte("<html>用户自己改过的挑战页</html>")
	if err := os.WriteFile(target, custom, 0644); err != nil {
		t.Fatal(err)
	}

	// 第二次释放（模拟升级）
	if err := ReleaseFiles(testPack, "testdata/pack", dir, "pack"); err != nil {
		t.Fatalf("再次释放失败: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(custom) {
		t.Fatalf("用户改过的文件被覆盖了，实际内容: %s", string(got))
	}
	if _, err := os.Stat(target + ".new"); err != nil {
		t.Fatalf("新版本应另存为 .new 供用户比对: %v", err)
	}
}

// 用户没动过的文件仍然要正常升级，否则修复补丁发不出去
func TestReleaseFiles_UpdatesUntouchedFile(t *testing.T) {
	dir := t.TempDir()
	if err := ReleaseFiles(testPack, "testdata/pack", dir, "pack"); err != nil {
		t.Fatalf("首次释放失败: %v", err)
	}
	target := filepath.Join(dir, "index.html")
	want, _ := testPack.ReadFile("testdata/pack/index.html")

	// 把文件删掉再释放，等价于内容变更后重新下发
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseFiles(testPack, "testdata/pack", dir, "pack"); err != nil {
		t.Fatalf("再次释放失败: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("未被改动的文件应正常释放: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("释放内容不一致")
	}
	if _, err := os.Stat(target + ".new"); err == nil {
		t.Fatalf("未被改动的文件不该产生 .new")
	}
}
