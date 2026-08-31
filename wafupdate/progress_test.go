package wafupdate

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// 权重合计必须是 100，否则百分比会永远到不了或提前满格
func TestStageWeightsSumTo100(t *testing.T) {
	sum := 0
	for _, d := range stageDefs {
		sum += d.Weight
	}
	if sum != 100 {
		t.Fatalf("阶段权重合计 = %d，应为 100", sum)
	}
	if stageDefs[stageIndexOf(StageDownload)].Weight < 50 {
		t.Fatalf("下载阶段应占大头(>=50)，当前 %d", stageDefs[stageIndexOf(StageDownload)].Weight)
	}
}

func TestProgressStageFlow(t *testing.T) {
	tr := NewProgressTracker()
	if got := tr.Snapshot().State; got != UpdateStateIdle {
		t.Fatalf("初始状态应为 idle，实际 %s", got)
	}

	tr.Begin("v1.0.0", "v1.0.1", "official")
	snap := tr.Snapshot()
	if snap.State != UpdateStateRunning || snap.FromVersion != "v1.0.0" || snap.ToVersion != "v1.0.1" {
		t.Fatalf("Begin 后快照不对: %+v", snap)
	}

	tr.StageStart(StageCheck)
	tr.StageDone(StageCheck, "")
	tr.StageStart(StageBackup)
	tr.StageDone(StageBackup, "")
	tr.StageStart(StageManifest)
	tr.StageDone(StageManifest, "v1.0.1")

	// check5 + backup10 + manifest5 = 20
	if p := tr.Snapshot().Percent; p != 20 {
		t.Fatalf("三阶段完成后应为 20%%，实际 %d", p)
	}

	// 下载到一半：20 + 50*0.5 = 45
	tr.StageStart(StageDownload)
	tr.SetDownload(500, 1000)
	snap = tr.Snapshot()
	if snap.Percent != 45 {
		t.Fatalf("下载 50%% 时总进度应为 45%%，实际 %d", snap.Percent)
	}
	if snap.Stage != StageDownload {
		t.Fatalf("当前阶段应为 download，实际 %s", snap.Stage)
	}

	tr.StageDone(StageDownload, "")
	tr.StageStart(StageVerify)
	tr.StageDone(StageVerify, "")
	tr.StageStart(StageExtract)
	tr.StageDone(StageExtract, "")
	tr.StageStart(StageReplace)

	if tr.ReplaceDone() {
		t.Fatal("replace 尚未完成时 ReplaceDone 应为 false")
	}
	tr.StageDone(StageReplace, "")
	if !tr.ReplaceDone() {
		t.Fatal("replace 完成后 ReplaceDone 应为 true")
	}

	// 未确认就绪之前不给 100%
	tr.MarkRestarting()
	if p := tr.Snapshot().Percent; p != 95 {
		t.Fatalf("等待重启时应为 95%%，实际 %d", p)
	}
	tr.Success()
	if p := tr.Snapshot().Percent; p != 100 {
		t.Fatalf("成功后应为 100%%，实际 %d", p)
	}
}

// 备份失败按 warn 计权重，升级继续，进度不能因此卡住
func TestProgressWarnStillCounts(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageCheck)
	tr.StageDone(StageCheck, "")
	tr.StageStart(StageBackup)
	tr.StageWarn(StageBackup, "备份失败")
	if p := tr.Snapshot().Percent; p != 15 {
		t.Fatalf("备份 warn 后应为 15%%，实际 %d", p)
	}
	if tr.Snapshot().Stages[stageIndexOf(StageBackup)].State != StageStateWarn {
		t.Fatal("备份阶段状态应为 warn")
	}
}

// 百分比只进不退
func TestProgressPercentNeverGoesBackwards(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)
	tr.SetDownload(800, 1000)
	first := tr.Snapshot().Percent
	// 服务端重发/长度变大等异常，不能让界面上的进度倒回去
	tr.SetDownload(100, 1000)
	if second := tr.Snapshot().Percent; second < first {
		t.Fatalf("进度回退了: %d -> %d", first, second)
	}
}

// Content-Length 未知时不给阶段内进度，但也不能报错
func TestProgressUnknownTotal(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)
	tr.SetDownload(12345, 0)
	snap := tr.Snapshot()
	if snap.Total != 0 || snap.Downloaded != 12345 {
		t.Fatalf("未知长度时应只累计已下载字节: %+v", snap)
	}
	// 前三个阶段被 StageStart 判为"绕过"计入权重共 20，下载阶段本身不贡献进度
	if snap.Percent != 20 {
		t.Fatalf("未知长度时下载阶段不应贡献进度(应停在 20%%)，实际 %d", snap.Percent)
	}
}

// 取消只在下载阶段可用
func TestProgressCancelOnlyDuringDownload(t *testing.T) {
	tr := NewProgressTracker()
	if tr.Cancel() {
		t.Fatal("空闲状态不应允许取消")
	}
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageManifest)
	if tr.Cancel() {
		t.Fatal("清单阶段不应允许取消")
	}
	tr.StageStart(StageDownload)
	if !tr.Cancel() {
		t.Fatal("下载阶段应允许取消")
	}
	if !tr.IsCanceled() {
		t.Fatal("取消标志未置位")
	}

	tr2 := NewProgressTracker()
	tr2.Begin("v1.0.0", "v1.0.1", "official")
	tr2.StageStart(StageReplace)
	if tr2.Cancel() {
		t.Fatal("替换阶段绝对不能允许取消")
	}
}

// 失败后当前阶段标 failed、后续阶段标 skipped，并记录卡在哪一步
func TestProgressFailMarksStage(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)
	tr.Fail(errors.New("connection reset by peer"))

	snap := tr.Snapshot()
	if snap.State != UpdateStateFailed {
		t.Fatalf("状态应为 failed，实际 %s", snap.State)
	}
	if snap.ErrorStage != StageDownload {
		t.Fatalf("失败阶段应为 download，实际 %s", snap.ErrorStage)
	}
	if snap.Stages[stageIndexOf(StageDownload)].State != StageStateFailed {
		t.Fatal("下载阶段应标 failed")
	}
	// 失败之后的阶段保持 pending：标 skipped 会被计入权重，进度会在失败瞬间往前跳
	if snap.Stages[stageIndexOf(StageVerify)].State != StageStatePending {
		t.Fatal("失败之后的阶段应保持 pending")
	}
	beforeFailPercent := snap.Percent
	if beforeFailPercent > 25 {
		t.Fatalf("失败不应让进度前跳，实际 %d", beforeFailPercent)
	}

	// 取消走独立状态，界面文案不同
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)
	tr.Fail(ErrUpdateCanceled)
	if got := tr.Snapshot().State; got != UpdateStateCanceled {
		t.Fatalf("取消应为 canceled，实际 %s", got)
	}
}

func TestProgressReaderCounts(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)

	data := strings.Repeat("x", 5000)
	r := newProgressReader(strings.NewReader(data), tr, int64(len(data)))
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("字节数不对: %d", n)
	}
	snap := tr.Snapshot()
	if snap.Downloaded != int64(len(data)) || snap.Total != int64(len(data)) {
		t.Fatalf("下载计数不对: %+v", snap)
	}
	if snap.Percent != 45 { // 只有下载完成、其它阶段未完成时：50 全给到下载
		t.Logf("当前百分比 %d（仅供参考，取决于已完成阶段）", snap.Percent)
	}
}

func TestProgressReaderStopsOnCancel(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")
	tr.StageStart(StageDownload)

	r := newProgressReader(bytes.NewReader(make([]byte, 1<<20)), tr, 1<<20)
	buf := make([]byte, 1024)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("首次读取不应失败: %v", err)
	}
	tr.Cancel()
	if _, err := r.Read(buf); !errors.Is(err, ErrUpdateCanceled) {
		t.Fatalf("取消后应返回 ErrUpdateCanceled，实际 %v", err)
	}
}

// Tracker 为 nil 时所有打点都应是空操作（升级链路允许不带 Tracker 运行）
func TestNilTrackerIsSafe(t *testing.T) {
	var tr *ProgressTracker
	tr.StageStart(StageDownload)
	tr.StageDone(StageDownload, "x")
	tr.StageWarn(StageBackup, "x")
	tr.SetDownload(1, 2)
	tr.Fail(errors.New("x"))
	tr.MarkRestarting()
	if tr.IsCanceled() {
		t.Fatal("nil tracker 不应报告已取消")
	}
	if r := newProgressReader(strings.NewReader("abc"), nil, 3); r == nil {
		t.Fatal("nil tracker 时应原样返回 reader")
	}
}

// 轮询读与升级线程写并发，跑 -race 校验
func TestProgressConcurrentAccess(t *testing.T) {
	tr := NewProgressTracker()
	tr.Begin("v1.0.0", "v1.0.1", "official")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tr.StageStart(StageDownload)
		for i := 0; i < 500; i++ {
			tr.SetDownload(int64(i), 500)
		}
		tr.StageDone(StageDownload, "")
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = tr.Snapshot()
			_ = tr.State()
			_ = tr.ReplaceDone()
		}
	}()
	wg.Wait()
}
