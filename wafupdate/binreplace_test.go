package wafupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUniqueOldPathNeverCollides 核心修复的直接断言：
// 即便同名目标已存在，uniqueOldPath 也必须给出一个尚不存在的新路径。
// 旧实现用固定名 ".<exe>.old"，目标一旦残留且被占用，rename 就 ACCESS_DENIED。
func TestUniqueOldPathNeverCollides(t *testing.T) {
	dir := t.TempDir()
	exe := "SamWaf64.exe"

	// 预置一个"删不掉的残留"同名文件（内容无所谓，存在即可）
	if err := os.WriteFile(filepath.Join(dir, oldPrefix(exe)), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		p := uniqueOldPath(dir, exe)
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("uniqueOldPath 返回了已存在的路径: %s", p)
		}
		if seen[p] {
			t.Fatalf("uniqueOldPath 返回了重复路径: %s", p)
		}
		seen[p] = true
		// 占位，模拟这一轮升级已经把它用掉了
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(filepath.Base(p), oldPrefix(exe)) {
			t.Fatalf("命名未落在 .old 前缀下: %s", p)
		}
	}
}

// TestSweepLeftoversOnlyTouchesOwnTemps 清扫必须只动自己的临时文件，
// 且不碰主程序与目录里的其它文件。
func TestSweepLeftoversOnlyTouchesOwnTemps(t *testing.T) {
	dir := t.TempDir()
	exe := "SamWaf64.exe"

	mustWrite := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old1 := mustWrite(oldPrefix(exe) + ".20260101010101.111")
	old2 := mustWrite(oldPrefix(exe) + ".20260101010102.222")
	newFile := mustWrite("." + exe + stageNewSuffix)
	keepExe := mustWrite(exe)
	keepOther := mustWrite("other.txt")
	keepOtherExeOld := mustWrite(".OtherApp.exe.old")

	// 把 .old 的时间戳改老，绕开"跳过 60s 内新建文件"的并发保护
	aged := time.Now().Add(-10 * time.Minute)
	for _, p := range []string{old1, old2, newFile} {
		if err := os.Chtimes(p, aged, aged); err != nil {
			t.Fatal(err)
		}
	}

	removed, kept := sweepLeftovers(dir, exe, true)
	if removed != 3 || kept != 0 {
		t.Fatalf("期望删除 3 个/保留 0 个，实际 removed=%d kept=%d", removed, kept)
	}
	for _, p := range []string{old1, old2, newFile} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("应被清扫却仍在: %s", p)
		}
	}
	for _, p := range []string{keepExe, keepOther, keepOtherExeOld} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("不该被动却没了: %s", p)
		}
	}
}

// TestSweepLeftoversSkipsRecent 刚创建的 .old 可能属于另一个正在进行中的替换
// （例如服务运行中同时执行 samwaf rollback），必须跳过。
func TestSweepLeftoversSkipsRecent(t *testing.T) {
	dir := t.TempDir()
	exe := "SamWaf64.exe"
	fresh := filepath.Join(dir, oldPrefix(exe)+".20260101010101.333")
	if err := os.WriteFile(fresh, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	removed, kept := sweepLeftovers(dir, exe, false)
	if removed != 0 || kept != 1 {
		t.Fatalf("期望删除 0 个/保留 1 个，实际 removed=%d kept=%d", removed, kept)
	}
	if _, err := os.Lstat(fresh); err != nil {
		t.Fatalf("刚创建的 .old 不该被删: %v", err)
	}
}

// TestSweepLeftoversKeepsStagingWhenNotIncluded replaceExecutable 途中调用清扫时，
// 本次的 .new/.rollback 正在使用，绝不能被扫掉。
func TestSweepLeftoversKeepsStagingWhenNotIncluded(t *testing.T) {
	dir := t.TempDir()
	exe := "SamWaf64.exe"
	staging := filepath.Join(dir, "."+exe+stageNewSuffix)
	if err := os.WriteFile(staging, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	aged := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(staging, aged, aged); err != nil {
		t.Fatal(err)
	}

	sweepLeftovers(dir, exe, false) // includeStaging=false
	if _, err := os.Lstat(staging); err != nil {
		t.Fatalf("includeStaging=false 时 .new 不该被删: %v", err)
	}
}

// TestRetryFileOpStopsOnPermanentError 确定性错误不该白白重试等待。
func TestRetryFileOpStopsOnPermanentError(t *testing.T) {
	calls := 0
	permanent := errors.New("permanent failure")
	start := time.Now()
	err := retryFileOp("test", 5, func() error {
		calls++
		return permanent
	})
	if !errors.Is(err, permanent) {
		t.Fatalf("期望原样返回确定性错误，实际 %v", err)
	}
	if calls != 1 {
		t.Fatalf("确定性错误应只尝试 1 次，实际 %d 次", calls)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("确定性错误不该退避等待，耗时 %v", time.Since(start))
	}
}

// TestRetryFileOpTreatsMissingAsSuccess 删除操作要幂等。
func TestRetryFileOpTreatsMissingAsSuccess(t *testing.T) {
	err := retryFileOp("test", 3, func() error {
		return os.ErrNotExist
	})
	if err != nil {
		t.Fatalf("文件不存在应视为成功，实际 %v", err)
	}
}

// TestReplaceExecutableSwapsAndKeepsUniqueOld 替换的正常路径：
// 新内容就位、旧内容被搬走、且 .old 用的是唯一名（不是固定名）。
func TestReplaceExecutableSwapsAndKeepsUniqueOld(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "SamWaf64.exe")
	staged := filepath.Join(dir, ".SamWaf64.exe"+stageNewSuffix)

	if err := os.WriteFile(exe, []byte("OLD"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("NEW"), 0755); err != nil {
		t.Fatal(err)
	}

	err, recoverErr := replaceExecutable(exe, staged)
	if err != nil || recoverErr != nil {
		t.Fatalf("替换应成功，实际 err=%v recoverErr=%v", err, recoverErr)
	}

	got, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "NEW" {
		t.Fatalf("主程序内容应为 NEW，实际 %q", string(got))
	}
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged 文件应已被搬走: %v", err)
	}
	// 固定名 .old 不该出现——那正是旧实现踩坑的地方
	if _, err := os.Lstat(filepath.Join(dir, oldPrefix("SamWaf64.exe"))); !os.IsNotExist(err) {
		t.Fatalf("不应生成固定名 .old")
	}
}

// TestReplaceExecutableWithUndeletableOldLeftover 本 bug 的回归测试。
//
// 场景：上一次升级留下的 .old 还在（生产上它是常驻 Supervisor 的映像，删不掉）。
// 旧实现会把它当作 rename 目标 → Windows 上 ACCESS_DENIED。
// 新实现用唯一名，必须照常成功，且不动那个残留。
func TestReplaceExecutableWithUndeletableOldLeftover(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "SamWaf64.exe")
	staged := filepath.Join(dir, ".SamWaf64.exe"+stageNewSuffix)
	leftover := filepath.Join(dir, oldPrefix("SamWaf64.exe"))

	for p, c := range map[string]string{exe: "OLD", staged: "NEW", leftover: "PINNED"} {
		if err := os.WriteFile(p, []byte(c), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// 保鲜时间戳，让 sweepLeftovers 跳过它，模拟"扫不掉的残留"
	now := time.Now()
	if err := os.Chtimes(leftover, now, now); err != nil {
		t.Fatal(err)
	}

	err, recoverErr := replaceExecutable(exe, staged)
	if err != nil || recoverErr != nil {
		t.Fatalf("有残留 .old 时替换仍应成功，实际 err=%v recoverErr=%v", err, recoverErr)
	}

	got, _ := os.ReadFile(exe)
	if string(got) != "NEW" {
		t.Fatalf("主程序内容应为 NEW，实际 %q", string(got))
	}
	pinned, readErr := os.ReadFile(leftover)
	if readErr != nil || string(pinned) != "PINNED" {
		t.Fatalf("残留 .old 不该被改动，读到 %q err=%v", string(pinned), readErr)
	}
}

// TestCurrentRoleFollowsWorkerFlag 诊断信息里的角色判定要与 parseWorkerRole 一致。
func TestCurrentRoleFollowsWorkerFlag(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()

	os.Args = []string{"SamWaf64.exe"}
	if got := currentRole(); got != "Supervisor" {
		t.Fatalf("无 --worker 时应为 Supervisor，实际 %s", got)
	}
	os.Args = []string{"SamWaf64.exe", "--worker", "--ctrl-addr=127.0.0.1:1"}
	if got := currentRole(); got != "Worker" {
		t.Fatalf("有 --worker 时应为 Worker，实际 %s", got)
	}
}
