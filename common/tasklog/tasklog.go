package tasklog

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ---- goroutine 上下文：goroutine ID -> task method ----

var goroutineTaskMap sync.Map // key: int64(goroutine ID), value: string(task method)

// goroutineID 解析当前 goroutine 的 ID（通过 runtime.Stack）
func goroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	s := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		return -1
	}
	id, _ := strconv.ParseInt(s[:idx], 10, 64)
	return id
}

// SetCurrentTask 在当前 goroutine 上注册正在执行的任务方法名
func SetCurrentTask(taskMethod string) {
	goroutineTaskMap.Store(goroutineID(), taskMethod)
}

// ClearCurrentTask 清除当前 goroutine 的任务上下文
func ClearCurrentTask() {
	goroutineTaskMap.Delete(goroutineID())
}

// GetCurrentTask 获取当前 goroutine 关联的任务方法名（若无则返回 "", false）
func GetCurrentTask() (string, bool) {
	v, ok := goroutineTaskMap.Load(goroutineID())
	if !ok {
		return "", false
	}
	return v.(string), true
}

// ---- 自定义 zap Core：将 zlog 输出路由到任务日志文件 ----

// TaskZapCore 是一个 zapcore.Core 实现
// 它在当前 goroutine 有任务上下文时，把日志同步写入对应的任务日志文件
type TaskZapCore struct {
	minLevel zapcore.Level
}

// NewTaskZapCore 创建 TaskZapCore，minLevel 决定哪些级别的日志写入任务文件
func NewTaskZapCore(minLevel zapcore.Level) zapcore.Core {
	return &TaskZapCore{minLevel: minLevel}
}

func (c *TaskZapCore) Enabled(level zapcore.Level) bool {
	return level >= c.minLevel
}

func (c *TaskZapCore) With(_ []zapcore.Field) zapcore.Core {
	return c
}

func (c *TaskZapCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(entry.Level) {
		return ce
	}
	if GlobalTaskLogManager == nil {
		return ce
	}
	if _, ok := GetCurrentTask(); !ok {
		return ce
	}
	return ce.AddCore(entry, c)
}

func (c *TaskZapCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if GlobalTaskLogManager == nil {
		return nil
	}
	taskMethod, ok := GetCurrentTask()
	if !ok {
		return nil
	}
	level := strings.ToUpper(entry.Level.String())

	msg := entry.Message
	if len(fields) > 0 {
		enc := zapcore.NewMapObjectEncoder()
		for _, f := range fields {
			f.AddTo(enc)
		}
		var extras []string
		for k, v := range enc.Fields {
			extras = append(extras, fmt.Sprintf("%s=%v", k, v))
		}
		if len(extras) > 0 {
			msg = msg + " " + strings.Join(extras, " ")
		}
	}

	GlobalTaskLogManager.Log(taskMethod, level, msg)
	return nil
}

func (c *TaskZapCore) Sync() error {
	return nil
}

// ---- TaskLogManager ----

// rateLimitState 记录某个任务的速率限制状态
type rateLimitState struct {
	lastWriteTime   time.Time
	suppressedCount int64
}

// TaskLogManager 任务日志管理器，为每个任务方法维护独立的日志文件
type TaskLogManager struct {
	logDir     string
	retainDays int // 全局默认保留天数

	// writer 相关（受 mu 保护）
	mu             sync.RWMutex
	writers        map[string]*lumberjack.Logger
	taskRetainDays map[string]int // md5(taskMethod) -> 覆盖保留天数（0 = 使用全局 retainDays）

	// 速率限制相关（受各自 mutex 保护）
	policyMu   sync.RWMutex
	policies   map[string]time.Duration // taskMethod -> 最小写入间隔（0 = 不限制）
	rateMu     sync.Mutex
	rateStates map[string]*rateLimitState // taskMethod -> 速率限制状态
}

// GlobalTaskLogManager 全局任务日志管理器单例
var GlobalTaskLogManager *TaskLogManager

// InitGlobalTaskLogManager 初始化全局任务日志管理器
func InitGlobalTaskLogManager(logDir string, retainDays int) {
	if retainDays <= 0 {
		retainDays = 30
	}
	GlobalTaskLogManager = &TaskLogManager{
		logDir:         logDir,
		retainDays:     retainDays,
		writers:        make(map[string]*lumberjack.Logger),
		taskRetainDays: make(map[string]int),
		policies:       make(map[string]time.Duration),
		rateStates:     make(map[string]*rateLimitState),
	}
	_ = os.MkdirAll(logDir, 0755)
}

// methodMD5 计算任务方法名的 MD5，用作文件名
func methodMD5(taskMethod string) string {
	h := md5.New()
	_, _ = io.WriteString(h, taskMethod)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GetLogFilePath 根据任务方法名返回其日志文件的完整路径
func (m *TaskLogManager) GetLogFilePath(taskMethod string) string {
	return filepath.Join(m.logDir, methodMD5(taskMethod)+".log")
}

// getEffectiveRetainDays 获取任务实际使用的保留天数（优先使用任务级别覆盖值）
func (m *TaskLogManager) getEffectiveRetainDays(key string) int {
	if days, ok := m.taskRetainDays[key]; ok && days > 0 {
		return days
	}
	return m.retainDays
}

// getWriter 获取或创建对应任务方法的 lumberjack 写入器（内部加锁）
func (m *TaskLogManager) getWriter(taskMethod string) *lumberjack.Logger {
	key := methodMD5(taskMethod)

	m.mu.RLock()
	w, ok := m.writers[key]
	m.mu.RUnlock()
	if ok {
		return w
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok = m.writers[key]; ok {
		return w
	}

	logFilePath := filepath.Join(m.logDir, key+".log")
	w = &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50,
		MaxBackups: 10,
		MaxAge:     m.getEffectiveRetainDays(key),
		Compress:   false,
	}
	m.writers[key] = w
	return w
}

// SetTaskRetainDays 为指定任务设置独立的日志保留天数（覆盖全局配置）
// days <= 0 表示使用全局默认值
func (m *TaskLogManager) SetTaskRetainDays(taskMethod string, days int) {
	if m == nil {
		return
	}
	key := methodMD5(taskMethod)
	m.mu.Lock()
	defer m.mu.Unlock()
	if days > 0 {
		m.taskRetainDays[key] = days
	} else {
		delete(m.taskRetainDays, key)
	}
	// 如果 writer 已存在，同步更新其 MaxAge
	if w, ok := m.writers[key]; ok {
		w.MaxAge = m.getEffectiveRetainDays(key)
	}
}

// SetTaskLogPolicy 为指定任务方法设置最小写入间隔（速率限制）
// minInterval == 0 表示不限制；> 0 时 INFO/DEBUG 按间隔压缩，ERROR/WARN 仍直写
func (m *TaskLogManager) SetTaskLogPolicy(taskMethod string, minInterval time.Duration) {
	if m == nil {
		return
	}
	m.policyMu.Lock()
	m.policies[taskMethod] = minInterval
	m.policyMu.Unlock()
}

// getPolicy 获取任务的最小写入间隔（0 = 不限）
func (m *TaskLogManager) getPolicy(taskMethod string) time.Duration {
	m.policyMu.RLock()
	d := m.policies[taskMethod]
	m.policyMu.RUnlock()
	return d
}

// Log 写入一条任务日志
// ERROR / WARN 始终直接写入；INFO / DEBUG 受速率限制策略约束
func (m *TaskLogManager) Log(taskMethod, level, message string) {
	if m == nil {
		return
	}

	now := time.Now()
	w := m.getWriter(taskMethod)

	isHighPriority := level == "ERROR" || level == "WARN"
	minInterval := m.getPolicy(taskMethod)

	if minInterval <= 0 || isHighPriority {
		// 高优先级日志：先把积压的压缩摘要冲出来，再写本条
		if isHighPriority {
			m.flushSuppressed(taskMethod, w, now)
		}
		_, _ = w.Write([]byte(formatLogLine(now, level, taskMethod, message)))
		return
	}

	// INFO / DEBUG 受速率限制
	m.rateMu.Lock()
	state, ok := m.rateStates[taskMethod]
	if !ok {
		state = &rateLimitState{}
		m.rateStates[taskMethod] = state
	}

	if state.lastWriteTime.IsZero() || now.Sub(state.lastWriteTime) >= minInterval {
		suppressed := state.suppressedCount
		state.lastWriteTime = now
		state.suppressedCount = 0
		m.rateMu.Unlock()

		if suppressed > 0 {
			summary := formatLogLine(now, "INFO", taskMethod,
				fmt.Sprintf("(已压缩 %d 条日志)", suppressed))
			_, _ = w.Write([]byte(summary))
		}
		_, _ = w.Write([]byte(formatLogLine(now, level, taskMethod, message)))
	} else {
		state.suppressedCount++
		m.rateMu.Unlock()
	}
}

// flushSuppressed 在写高优先级日志前，把积压的压缩摘要冲出来
func (m *TaskLogManager) flushSuppressed(taskMethod string, w *lumberjack.Logger, now time.Time) {
	m.rateMu.Lock()
	state, ok := m.rateStates[taskMethod]
	if !ok || state.suppressedCount == 0 {
		m.rateMu.Unlock()
		return
	}
	suppressed := state.suppressedCount
	state.suppressedCount = 0
	state.lastWriteTime = now
	m.rateMu.Unlock()

	_, _ = w.Write([]byte(formatLogLine(now, "INFO", taskMethod,
		fmt.Sprintf("(已压缩 %d 条日志)", suppressed))))
}

// formatLogLine 格式化一行日志
func formatLogLine(t time.Time, level, taskMethod, message string) string {
	return fmt.Sprintf("[%s] [%s] [%s] %s\n",
		t.Format("2006-01-02 15:04:05"),
		level,
		taskMethod,
		message,
	)
}

// LogResult 是 ReadLog 的返回值
type LogResult struct {
	Content   string `json:"content"`
	NewOffset int64  `json:"new_offset"`
	LogFile   string `json:"log_file"`
	FileSize  int64  `json:"file_size"`
}

// ReadLog 读取任务日志
// offset=0 从头读取；offset>0 增量读取新增内容
func (m *TaskLogManager) ReadLog(taskMethod string, lines int, offset int64) (*LogResult, error) {
	if m == nil {
		return &LogResult{}, nil
	}
	logFilePath := m.GetLogFilePath(taskMethod)

	f, err := os.Open(logFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &LogResult{LogFile: logFilePath}, nil
		}
		return nil, fmt.Errorf("打开日志文件失败: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取日志文件信息失败: %w", err)
	}
	fileSize := fi.Size()

	if offset > fileSize {
		offset = 0
	}

	if offset > 0 {
		if offset == fileSize {
			return &LogResult{NewOffset: fileSize, LogFile: logFilePath, FileSize: fileSize}, nil
		}
		_, err = f.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("定位日志文件失败: %w", err)
		}
		buf := make([]byte, fileSize-offset)
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取日志文件失败: %w", err)
		}
		return &LogResult{
			Content:   string(buf[:n]),
			NewOffset: offset + int64(n),
			LogFile:   logFilePath,
			FileSize:  fileSize,
		}, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("读取日志文件失败: %w", err)
	}

	content := string(data)
	if lines > 0 {
		content = tailLines(content, lines)
	}

	return &LogResult{
		Content:   content,
		NewOffset: fileSize,
		LogFile:   logFilePath,
		FileSize:  fileSize,
	}, nil
}

// tailLines 返回文本最后 n 行
func tailLines(text string, n int) string {
	if n <= 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) <= n {
		return strings.Join(lines, "\n") + "\n"
	}
	return strings.Join(lines[len(lines)-n:], "\n") + "\n"
}

// ClearLog 清空指定任务的日志文件
func (m *TaskLogManager) ClearLog(taskMethod string) error {
	if m == nil {
		return nil
	}
	logFilePath := m.GetLogFilePath(taskMethod)

	key := methodMD5(taskMethod)
	m.mu.Lock()
	if w, ok := m.writers[key]; ok {
		_ = w.Close()
		delete(m.writers, key)
	}
	m.mu.Unlock()

	f, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("清空日志文件失败: %w", err)
	}
	return f.Close()
}

// CleanExpiredLogs 扫描日志目录，删除超过各任务保留策略的过期备份文件
func (m *TaskLogManager) CleanExpiredLogs() {
	if m == nil {
		return
	}
	// 使用全局 retainDays 作为兜底清理基准（单个任务的短保留由 lumberjack MaxAge 自行处理）
	cutoff := time.Now().AddDate(0, 0, -m.retainDays)

	entries, err := os.ReadDir(m.logDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".log") &&
			!strings.HasSuffix(name, ".gz") &&
			!strings.Contains(name, ".log-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(m.logDir, name))
		}
	}
}

// UpdateRetainDays 动态更新全局默认保留天数，并刷新未被任务级别覆盖的 writer
func (m *TaskLogManager) UpdateRetainDays(days int) {
	if m == nil || days <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retainDays = days
	for key, w := range m.writers {
		// 只更新没有任务级别覆盖的 writer
		if _, hasOverride := m.taskRetainDays[key]; !hasOverride {
			w.MaxAge = days
		}
	}
}
