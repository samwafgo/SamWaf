package wafupdate

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// 升级阶段 key。数组顺序即执行顺序，权重之和恒为 100（progress_test.go 有守护用例）。
const (
	StageCheck    = "check"
	StageBackup   = "backup"
	StageManifest = "manifest"
	StageDownload = "download"
	StageVerify   = "verify"
	StageExtract  = "extract"
	StageReplace  = "replace"
	StageRestart  = "restart"
)

// 升级整体状态
const (
	UpdateStateIdle       = "idle"
	UpdateStateRunning    = "running"
	UpdateStateRestarting = "restarting"
	UpdateStateSuccess    = "success"
	UpdateStateFailed     = "failed"
	UpdateStateCanceled   = "canceled"
)

// 单个阶段的状态
const (
	StageStatePending = "pending"
	StageStateRunning = "running"
	StageStateDone    = "done"
	StageStateWarn    = "warn" // 出了问题但不阻断升级，例如备份失败
	StageStateFailed  = "failed"
	StageStateSkipped = "skipped"
)

// ErrUpdateCanceled 用户在下载阶段主动取消。只有下载阶段可取消：
// 进入二进制替换后中断反而危险。
var ErrUpdateCanceled = errors.New("升级已被用户取消")

type stageDef struct {
	Key    string
	Weight int
}

// 权重是经验值，只保证"下载占大头且是真百分比"。其余阶段没有阶段内进度，
// 到达即停在本档起点，完成才跳下一档——不做假的匀速插值。
var stageDefs = []stageDef{
	{StageCheck, 5},
	{StageBackup, 10},
	{StageManifest, 5},
	{StageDownload, 50},
	{StageVerify, 10},
	{StageExtract, 10},
	{StageReplace, 5},
	{StageRestart, 5},
}

// StageSnapshot 单阶段对外快照
type StageSnapshot struct {
	Key    string `json:"key"`
	State  string `json:"state"`
	CostMs int64  `json:"cost_ms"`
	Detail string `json:"detail"`
}

// ProgressSnapshot 升级进度对外快照
type ProgressSnapshot struct {
	State       string          `json:"state"`
	Stage       string          `json:"stage"`
	StageIndex  int             `json:"stage_index"`
	Percent     int             `json:"percent"`
	Downloaded  int64           `json:"downloaded"`
	Total       int64           `json:"total"` // 0 = 服务端未给 Content-Length
	Speed       int64           `json:"speed"` // 字节/秒
	FromVersion string          `json:"from_version"`
	ToVersion   string          `json:"to_version"`
	Channel     string          `json:"channel"`
	StartedAt   int64           `json:"started_at"`
	Error       string          `json:"error"`
	ErrorStage  string          `json:"error_stage"`
	Stages      []StageSnapshot `json:"stages"`
}

type stageState struct {
	state   string
	detail  string
	startAt time.Time
	costMs  int64
}

// ProgressTracker 升级进度快照。刻意只放内存不落库：
// 升级是单实例的瞬时行为，重启之后本就该从"探测新版本号"接续，落库没有意义。
type ProgressTracker struct {
	mu          sync.RWMutex
	state       string
	from        string
	to          string
	channel     string
	startedAt   time.Time
	stages      []stageState
	curIdx      int // -1 表示尚未进入任何阶段
	downloaded  int64
	total       int64
	speed       int64
	dlStartedAt time.Time
	lastPercent int
	errMsg      string
	errStage    string
	canceled    atomic.Bool
}

// GlobalUpdateProgress 全局唯一的升级进度。与 global.GWAF_RUNTIME_IS_UPDATETING
// 同步置位：后者仍是并发互斥闸，这里只负责"说清楚跑到哪一步了"。
var GlobalUpdateProgress = NewProgressTracker()

func NewProgressTracker() *ProgressTracker {
	t := &ProgressTracker{curIdx: -1, state: UpdateStateIdle}
	t.resetStages()
	return t
}

func (t *ProgressTracker) resetStages() {
	t.stages = make([]stageState, len(stageDefs))
	for i := range t.stages {
		t.stages[i].state = StageStatePending
	}
}

func stageIndexOf(key string) int {
	for i, d := range stageDefs {
		if d.Key == key {
			return i
		}
	}
	return -1
}

// Begin 开启一轮升级，清空上一轮的残留。
func (t *ProgressTracker) Begin(from, to, channel string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = UpdateStateRunning
	t.from, t.to, t.channel = from, to, channel
	t.startedAt = time.Now()
	t.resetStages()
	t.curIdx = -1
	t.downloaded, t.total, t.speed = 0, 0, 0
	t.lastPercent = 0
	t.errMsg, t.errStage = "", ""
	t.canceled.Store(false)
}

// StageStart 进入某阶段。nil receiver 安全，方便调用方不做判空。
func (t *ProgressTracker) StageStart(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	i := stageIndexOf(key)
	if i < 0 {
		return
	}
	// 中间被跳过的阶段（如 GitHub 渠道不做 SHA 校验）标 skipped，避免一直挂在 pending
	for j := 0; j < i; j++ {
		if t.stages[j].state == StageStatePending {
			t.stages[j].state = StageStateSkipped
		}
	}
	t.curIdx = i
	t.stages[i].state = StageStateRunning
	t.stages[i].startAt = time.Now()
	if key == StageDownload {
		t.dlStartedAt = time.Now()
	}
}

// StageDone 结束某阶段，detail 为空则保留原有 detail。
func (t *ProgressTracker) StageDone(key, detail string) {
	t.finishStage(key, StageStateDone, detail)
}

// StageWarn 阶段有问题但不阻断升级（当前只有备份失败会走这里）。
func (t *ProgressTracker) StageWarn(key, detail string) {
	t.finishStage(key, StageStateWarn, detail)
}

func (t *ProgressTracker) finishStage(key, state, detail string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	i := stageIndexOf(key)
	if i < 0 {
		return
	}
	t.stages[i].state = state
	if detail != "" {
		t.stages[i].detail = detail
	}
	if !t.stages[i].startAt.IsZero() {
		t.stages[i].costMs = time.Since(t.stages[i].startAt).Milliseconds()
	}
	if t.curIdx == i && i+1 < len(stageDefs) {
		t.curIdx = i + 1
	}
}

// SetDownload 刷新下载字节数与速率。
func (t *ProgressTracker) SetDownload(downloaded, total int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downloaded, t.total = downloaded, total
	if !t.dlStartedAt.IsZero() {
		if elapsed := time.Since(t.dlStartedAt).Seconds(); elapsed > 0.2 {
			t.speed = int64(float64(downloaded) / elapsed)
		}
	}
}

// Fail 以失败收尾，记录卡在哪个阶段。
func (t *ProgressTracker) Fail(err error) {
	if t == nil || err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// 取消位也参与判定：下载流经 gzip/tar 等中间层时，ErrUpdateCanceled 可能被包成别的错误
	if errors.Is(err, ErrUpdateCanceled) || t.canceled.Load() {
		t.state = UpdateStateCanceled
	} else {
		t.state = UpdateStateFailed
	}
	t.errMsg = err.Error()
	if t.curIdx >= 0 && t.curIdx < len(stageDefs) {
		t.errStage = stageDefs[t.curIdx].Key
		if t.stages[t.curIdx].state == StageStateRunning {
			t.stages[t.curIdx].state = StageStateFailed
			if !t.stages[t.curIdx].startAt.IsZero() {
				t.stages[t.curIdx].costMs = time.Since(t.stages[t.curIdx].startAt).Milliseconds()
			}
		}
		// 失败之后的阶段保持 pending：它们是"没走到"，不是"被绕过"。
		// 若标成 skipped 会被计入权重，界面上的进度会在失败瞬间反而往前跳。
	}
}

// MarkRestarting 二进制已替换完成，进入等待服务重启阶段。
// 此后 WebSocket 必断，界面靠轮询版本号判断是否就绪。
func (t *ProgressTracker) MarkRestarting() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = UpdateStateRestarting
	i := stageIndexOf(StageRestart)
	t.curIdx = i
	t.stages[i].state = StageStateRunning
	t.stages[i].startAt = time.Now()
}

// ReplaceDone 判断二进制替换是否真的完成。
// 用于识别"升级链路返回 nil 但其实什么都没做"的情况。
func (t *ProgressTracker) ReplaceDone() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	i := stageIndexOf(StageReplace)
	return t.stages[i].state == StageStateDone
}

// Cancel 请求取消。只在下载阶段有意义：计数 Reader 每次 Read 检查该标志。
// 返回 false 表示当前状态不允许取消。
func (t *ProgressTracker) Cancel() bool {
	t.mu.RLock()
	canCancel := t.state == UpdateStateRunning && t.curIdx == stageIndexOf(StageDownload)
	t.mu.RUnlock()
	if !canCancel {
		return false
	}
	t.canceled.Store(true)
	return true
}

func (t *ProgressTracker) IsCanceled() bool { return t != nil && t.canceled.Load() }

func (t *ProgressTracker) State() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state
}

// Snapshot 输出对外快照，百分比在此计算。
func (t *ProgressTracker) Snapshot() ProgressSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	snap := ProgressSnapshot{
		State:       t.state,
		StageIndex:  t.curIdx + 1, // 对外从 1 开始计
		Downloaded:  t.downloaded,
		Total:       t.total,
		Speed:       t.speed,
		FromVersion: t.from,
		ToVersion:   t.to,
		Channel:     t.channel,
		Error:       t.errMsg,
		ErrorStage:  t.errStage,
		Stages:      make([]StageSnapshot, 0, len(stageDefs)),
	}
	if !t.startedAt.IsZero() {
		snap.StartedAt = t.startedAt.Unix()
	}
	if t.curIdx >= 0 && t.curIdx < len(stageDefs) {
		snap.Stage = stageDefs[t.curIdx].Key
	}
	for i, d := range stageDefs {
		snap.Stages = append(snap.Stages, StageSnapshot{
			Key:    d.Key,
			State:  t.stages[i].state,
			CostMs: t.stages[i].costMs,
			Detail: t.stages[i].detail,
		})
	}

	switch t.state {
	case UpdateStateIdle:
		return snap
	case UpdateStateSuccess:
		snap.Percent = 100
		t.lastPercent = 100
		return snap
	}

	percent := 0
	for i, d := range stageDefs {
		switch t.stages[i].state {
		case StageStateDone, StageStateWarn, StageStateSkipped:
			percent += d.Weight
		case StageStateRunning:
			// 只有下载阶段有阶段内进度
			if d.Key == StageDownload && t.total > 0 {
				ratio := float64(t.downloaded) / float64(t.total)
				if ratio > 1 {
					ratio = 1
				}
				percent += int(float64(d.Weight) * ratio)
			}
		}
	}
	if percent > 99 && t.state != UpdateStateSuccess {
		percent = 99 // 只有确认就绪才给 100
	}
	// 百分比只进不退：阶段被标 skipped 之类的边界不该让进度倒回去
	if percent < t.lastPercent {
		percent = t.lastPercent
	}
	t.lastPercent = percent
	snap.Percent = percent
	return snap
}

// Success 升级完成（新版本已就绪）。当前由前端探测到新版本号后自然呈现，
// 后端进程此时已被替换重启，保留该方法供测试与后续扩展使用。
func (t *ProgressTracker) Success() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = UpdateStateSuccess
	i := stageIndexOf(StageRestart)
	t.stages[i].state = StageStateDone
}

// Reset 回到空闲态。
func (t *ProgressTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = UpdateStateIdle
	t.resetStages()
	t.curIdx = -1
	t.downloaded, t.total, t.speed, t.lastPercent = 0, 0, 0, 0
	t.errMsg, t.errStage = "", ""
	t.canceled.Store(false)
}

// progressReader 包住下载流做两件事：统计字节数、响应取消。
// 更新做了限频（≥200ms 或每 1%），避免 32KB 一块就写一次锁。
type progressReader struct {
	r          io.Reader
	t          *ProgressTracker
	total      int64
	read       int64
	lastNotify time.Time
	lastPct    int64
}

func newProgressReader(r io.Reader, t *ProgressTracker, total int64) io.Reader {
	if t == nil {
		return r
	}
	t.SetDownload(0, total)
	return &progressReader{r: r, t: t, total: total, lastNotify: time.Now()}
}

func (p *progressReader) Read(b []byte) (int, error) {
	if p.t.IsCanceled() {
		return 0, ErrUpdateCanceled
	}
	n, err := p.r.Read(b)
	if n > 0 {
		p.read += int64(n)
		notify := time.Since(p.lastNotify) >= 200*time.Millisecond
		if !notify && p.total > 0 {
			if pct := p.read * 100 / p.total; pct != p.lastPct {
				p.lastPct = pct
				notify = true
			}
		}
		if notify || err == io.EOF {
			p.lastNotify = time.Now()
			p.t.SetDownload(p.read, p.total)
		}
	}
	if err == io.EOF {
		p.t.SetDownload(p.read, p.total)
	}
	return n, err
}
