package wafappengine

import (
	"SamWaf/common/wafexec"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafappmodel"
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type netCacheEntry struct {
	result    *wafappmodel.NetStatsResult
	fetchedAt time.Time
}

const netCacheTTL = 30 * time.Second

type WafAppEngine struct {
	runtimes map[string]*wafappmodel.AppRuntime
	mu       sync.RWMutex
	netCache map[string]*netCacheEntry
	cacheMu  sync.RWMutex
}

func NewWafAppEngine() *WafAppEngine {
	return &WafAppEngine{
		runtimes: make(map[string]*wafappmodel.AppRuntime),
		netCache: make(map[string]*netCacheEntry),
	}
}

// StartApps 启动所有 AutoStart=1 且 StartStatus=1 的应用
func (e *WafAppEngine) StartApps() {
	var apps []model.WafApp
	global.GWAF_LOCAL_DB.Where("auto_start = 1 AND start_status = 1").Find(&apps)
	for _, app := range apps {
		if err := e.StartApp(app.Code); err != nil {
			zlog.Error("自动启动应用失败", "code", app.Code, "name", app.Name, "error", err.Error())
		}
	}
}

// StopApps 优雅关闭所有运行中的应用
func (e *WafAppEngine) StopApps() {
	e.mu.RLock()
	codes := make([]string, 0, len(e.runtimes))
	for code := range e.runtimes {
		codes = append(codes, code)
	}
	e.mu.RUnlock()

	var wg sync.WaitGroup
	for _, code := range codes {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			if err := e.StopApp(c); err != nil {
				zlog.Error("关闭应用失败", "code", c, "error", err.Error())
			}
		}(code)
	}
	wg.Wait()
}

// StartApp 启动单个应用
func (e *WafAppEngine) StartApp(code string) error {
	var app model.WafApp
	if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %s", code)
	}
	if app.StartStatus == 0 {
		return fmt.Errorf("应用已停用，不允许启动")
	}

	e.mu.Lock()
	rt, exists := e.runtimes[code]
	if exists && rt.Status == wafappmodel.AppStatusRunning {
		e.mu.Unlock()
		return fmt.Errorf("应用已在运行中")
	}
	stopChan := make(chan struct{})
	rt = &wafappmodel.AppRuntime{
		Code:     code,
		Status:   wafappmodel.AppStatusStopped,
		StopChan: stopChan,
	}
	if app.LogMaxLines <= 0 {
		app.LogMaxLines = 1000
	}
	e.runtimes[code] = rt
	e.mu.Unlock()

	return e.startProcess(app, rt)
}

func (e *WafAppEngine) startProcess(app model.WafApp, rt *wafappmodel.AppRuntime) error {
	appDir := app.AppDir
	if appDir == "" {
		appDir = "data/applications/" + app.Code
	}
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", app.StartCmd)
	} else {
		cmd = exec.Command("/bin/sh", "-c", app.StartCmd)
	}
	cmd.Dir = appDir

	// 纵深防御：拦截黑名单环境变量（即使 service 层已校验，防止 DB 直接写入绕过）
	engineEnvBlacklist := map[string]struct{}{
		"LD_PRELOAD": {}, "LD_LIBRARY_PATH": {}, "LD_AUDIT": {},
		"DYLD_INSERT_LIBRARIES": {}, "DYLD_LIBRARY_PATH": {}, "LD_PRELOAD_ONCE": {},
	}
	envs := append(os.Environ(), "")
	if app.Env != "" {
		for _, pair := range strings.Split(app.Env, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			eqIdx := strings.IndexByte(pair, '=')
			if eqIdx > 0 {
				key := strings.ToUpper(pair[:eqIdx])
				if _, blocked := engineEnvBlacklist[key]; blocked {
					zlog.Warn("引擎屏蔽黑名单环境变量", "key", pair[:eqIdx], "app", app.Code)
					continue
				}
			}
			envs = append(envs, pair)
		}
	}
	cmd.Env = envs

	// 只补 Stdin：下面要取 StdoutPipe/StderrPipe，Stdout/Stderr 必须留给 os/exec 自己接管
	wafexec.FixStdin(cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取stdout失败: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("获取stderr失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动进程失败: %w", err)
	}

	rt.Cmd = cmd
	rt.Pid = cmd.Process.Pid
	rt.Status = wafappmodel.AppStatusRunning
	rt.StartTime = time.Now()

	logFile, _ := os.OpenFile(appDir+"/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	logMaxLines := app.LogMaxLines
	if logMaxLines <= 0 {
		logMaxLines = 1000
	}

	rt.Done = make(chan struct{})
	go e.pipeReader(stdoutPipe, rt, logFile, logMaxLines)
	go e.pipeReader(stderrPipe, rt, logFile, logMaxLines)
	go e.monitorApp(app, rt)

	zlog.Info("应用已启动", "code", app.Code, "name", app.Name, "pid", rt.Pid)
	return nil
}

func decodeOutputLine(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	if runtime.GOOS == "windows" {
		if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw); err == nil {
			return string(decoded)
		}
	}
	return string(raw)
}

func (e *WafAppEngine) pipeReader(r io.Reader, rt *wafappmodel.AppRuntime, logFile *os.File, maxLines int) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := time.Now().Format("2006-01-02 15:04:05") + " " + decodeOutputLine(scanner.Bytes())
		rt.LogMu.Lock()
		rt.LogLines = append(rt.LogLines, line)
		if len(rt.LogLines) > maxLines {
			rt.LogLines = rt.LogLines[len(rt.LogLines)-maxLines:]
		}
		rt.LogMu.Unlock()
		if logFile != nil {
			logFile.WriteString(line + "\n")
		}
	}
}

func (e *WafAppEngine) monitorApp(app model.WafApp, rt *wafappmodel.AppRuntime) {
	defer close(rt.Done)
	for {
		err := rt.Cmd.Wait()

		select {
		case <-rt.StopChan:
			e.mu.Lock()
			rt.Status = wafappmodel.AppStatusStopped
			rt.Pid = 0
			e.mu.Unlock()
			zlog.Info("应用已主动停止", "code", app.Code, "name", app.Name)
			return
		default:
		}

		e.mu.Lock()
		rt.Status = wafappmodel.AppStatusCrashed
		rt.Pid = 0
		e.mu.Unlock()
		zlog.Warn("应用进程退出", "code", app.Code, "name", app.Name, "error", err)

		// 重新从数据库读取最新配置（可能已被更改）
		var latestApp model.WafApp
		if dbErr := global.GWAF_LOCAL_DB.Where("code = ?", app.Code).First(&latestApp).Error; dbErr != nil {
			zlog.Error("读取应用配置失败，停止监控", "code", app.Code, "name", app.Name)
			return
		}
		app = latestApp

		if app.StartStatus == 0 {
			return
		}
		if app.RestartPolicy == "no" || app.RestartPolicy == "" {
			return
		}
		if app.RestartPolicy == "on-failure" && err == nil {
			return
		}
		if app.MaxRestartCount > 0 && rt.RestartCount >= app.MaxRestartCount {
			zlog.Warn("已达最大重启次数，停止重启", "code", app.Code, "name", app.Name, "max", app.MaxRestartCount)
			return
		}

		delay := app.RestartDelay
		if delay <= 0 {
			delay = 5
		}
		zlog.Info("等待后重启应用", "code", app.Code, "name", app.Name, "delay_sec", delay)

		select {
		case <-rt.StopChan:
			e.mu.Lock()
			rt.Status = wafappmodel.AppStatusStopped
			e.mu.Unlock()
			return
		case <-time.After(time.Duration(delay) * time.Second):
		}

		// 重新检查 StopChan（等待期间可能已被关闭）
		select {
		case <-rt.StopChan:
			e.mu.Lock()
			rt.Status = wafappmodel.AppStatusStopped
			e.mu.Unlock()
			return
		default:
		}

		rt.RestartCount++
		zlog.Info("正在重启应用", "code", app.Code, "name", app.Name, "attempt", rt.RestartCount)

		appDir := app.AppDir
		if appDir == "" {
			appDir = "data/applications/" + app.Code
		}
		var newCmd *exec.Cmd
		if runtime.GOOS == "windows" {
			newCmd = exec.Command("cmd", "/C", app.StartCmd)
		} else {
			newCmd = exec.Command("/bin/sh", "-c", app.StartCmd)
		}
		newCmd.Dir = appDir
		envs := append(os.Environ(), "")
		if app.Env != "" {
			for _, pair := range strings.Split(app.Env, ",") {
				pair = strings.TrimSpace(pair)
				if pair != "" {
					envs = append(envs, pair)
				}
			}
		}
		newCmd.Env = envs

		// 只补 Stdin：下面要取 StdoutPipe/StderrPipe，Stdout/Stderr 必须留给 os/exec 自己接管
		wafexec.FixStdin(newCmd)

		stdoutPipe, _ := newCmd.StdoutPipe()
		stderrPipe, _ := newCmd.StderrPipe()
		if startErr := newCmd.Start(); startErr != nil {
			zlog.Error("重启应用失败", "code", app.Code, "name", app.Name, "error", startErr.Error())
			continue
		}

		logMaxLines := app.LogMaxLines
		if logMaxLines <= 0 {
			logMaxLines = 1000
		}

		e.mu.Lock()
		rt.Cmd = newCmd
		rt.Pid = newCmd.Process.Pid
		rt.Status = wafappmodel.AppStatusRunning
		rt.StartTime = time.Now()
		e.mu.Unlock()

		logFile, _ := os.OpenFile(appDir+"/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		go e.pipeReader(stdoutPipe, rt, logFile, logMaxLines)
		go e.pipeReader(stderrPipe, rt, logFile, logMaxLines)
		zlog.Info("应用重启成功", "code", app.Code, "name", app.Name, "pid", rt.Pid)
	}
}

// StopApp 停止单个应用
func (e *WafAppEngine) StopApp(code string) error {
	e.mu.RLock()
	rt, exists := e.runtimes[code]
	e.mu.RUnlock()
	if !exists || rt.Cmd == nil {
		return nil
	}

	var app model.WafApp
	global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app)

	// 1. 关闭 StopChan，阻止 monitorApp 重启循环
	select {
	case <-rt.StopChan:
	default:
		close(rt.StopChan)
	}

	// 2. 进程尚未启动，直接更新状态
	if rt.Cmd.Process == nil {
		e.mu.Lock()
		rt.Status = wafappmodel.AppStatusStopped
		rt.Pid = 0
		e.mu.Unlock()
		return nil
	}

	timeout := app.StopTimeout
	if timeout <= 0 {
		timeout = 30
	}

	// 3. 发送优雅关闭信号（不在此调用 Wait()，由 monitorApp 负责）
	if app.StopMode == "cmd" && app.StopCmd != "" {
		var stopCmd *exec.Cmd
		if runtime.GOOS == "windows" {
			stopCmd = exec.Command("cmd", "/C", app.StopCmd)
		} else {
			stopCmd = exec.Command("/bin/sh", "-c", app.StopCmd)
		}
		stopCmd.Dir = app.AppDir
		_ = wafexec.FixStdio(stopCmd).Run()
	} else {
		if runtime.GOOS == "windows" {
			// 发送 WM_CLOSE 给进程，给其机会优雅退出（不带 /F）
			wafexec.FixStdio(exec.Command("taskkill", "/PID", strconv.Itoa(rt.Pid))).Run()
		} else {
			rt.Cmd.Process.Signal(os.Interrupt)
		}
	}

	// 4. 等待 monitorApp 检测到进程退出并关闭 rt.Done；超时则强制终止整棵进程树
	select {
	case <-rt.Done:
		zlog.Info("应用已优雅停止", "code", code, "name", app.Name)
	case <-time.After(time.Duration(timeout) * time.Second):
		if runtime.GOOS == "windows" {
			// /F 强制 + /T 终止整棵子进程树，解决 cmd.exe 子进程孤儿问题
			wafexec.FixStdio(exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(rt.Pid))).Run()
		} else {
			if rt.Cmd.Process != nil {
				rt.Cmd.Process.Kill()
			}
		}
		zlog.Warn("应用强制终止", "code", code, "name", app.Name)
		// 等待 monitorApp 确认退出（最多再等 5s）
		select {
		case <-rt.Done:
		case <-time.After(5 * time.Second):
		}
	}

	e.mu.Lock()
	rt.Status = wafappmodel.AppStatusStopped
	rt.Pid = 0
	e.mu.Unlock()

	e.cacheMu.Lock()
	delete(e.netCache, code)
	e.cacheMu.Unlock()
	return nil
}

// RestartApp 重启单个应用
func (e *WafAppEngine) RestartApp(code string) error {
	_ = e.StopApp(code)
	// 重置 runtime，让 StartApp 重新创建
	e.mu.Lock()
	delete(e.runtimes, code)
	e.mu.Unlock()
	return e.StartApp(code)
}

// GetRuntimeStatus 获取运行时状态（线程安全的快照）
func (e *WafAppEngine) GetRuntimeStatus(code string) wafappmodel.AppRuntime {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rt, exists := e.runtimes[code]
	if !exists {
		return wafappmodel.AppRuntime{Code: code, Status: wafappmodel.AppStatusStopped}
	}
	return wafappmodel.AppRuntime{
		Code:         rt.Code,
		Pid:          rt.Pid,
		Status:       rt.Status,
		StartTime:    rt.StartTime,
		RestartCount: rt.RestartCount,
	}
}

// GetLogs 获取最近日志行
func (e *WafAppEngine) GetLogs(code string) []string {
	e.mu.RLock()
	rt, exists := e.runtimes[code]
	e.mu.RUnlock()
	if !exists {
		return nil
	}
	rt.LogMu.Lock()
	defer rt.LogMu.Unlock()
	result := make([]string, len(rt.LogLines))
	copy(result, rt.LogLines)
	return result
}

// ClearLogs 清空内存和文件日志
func (e *WafAppEngine) ClearLogs(code string) {
	e.mu.RLock()
	rt, exists := e.runtimes[code]
	e.mu.RUnlock()
	if exists {
		rt.LogMu.Lock()
		rt.LogLines = nil
		rt.LogMu.Unlock()
	}

	var app model.WafApp
	if global.GWAF_LOCAL_DB.Where("code = ?", code).First(&app).Error == nil {
		appDir := app.AppDir
		if appDir == "" {
			appDir = "data/applications/" + code
		}
		os.Truncate(appDir+"/app.log", 0)
	}
}

// LoadApp 热加载（新增/修改应用时调用）
func (e *WafAppEngine) LoadApp(app model.WafApp) {
	// 如果当前在运行，重启；否则忽略（等待手动启动）
	e.mu.RLock()
	rt, exists := e.runtimes[app.Code]
	e.mu.RUnlock()
	if exists && rt.Status == wafappmodel.AppStatusRunning {
		_ = e.RestartApp(app.Code)
	}
}

// RemoveApp 移除应用（删除时调用）
func (e *WafAppEngine) RemoveApp(code string) {
	_ = e.StopApp(code)
	e.mu.Lock()
	delete(e.runtimes, code)
	e.mu.Unlock()
}

// GetNetStats 返回应用占用的端口及连接 IP，结果缓存 30s
func (e *WafAppEngine) GetNetStats(code string) (*wafappmodel.NetStatsResult, error) {
	empty := &wafappmodel.NetStatsResult{
		Ports:       []wafappmodel.PortInfo{},
		Connections: []wafappmodel.ConnInfo{},
	}

	e.mu.RLock()
	rt, exists := e.runtimes[code]
	e.mu.RUnlock()
	if !exists || rt.Pid == 0 || rt.Status != wafappmodel.AppStatusRunning {
		return empty, nil
	}
	pid := rt.Pid

	e.cacheMu.RLock()
	cached := e.netCache[code]
	e.cacheMu.RUnlock()
	if cached != nil && time.Since(cached.fetchedAt) < netCacheTTL {
		return cached.result, nil
	}

	result, err := fetchNetStats(pid)
	if err != nil {
		return empty, err
	}
	result.CachedAt = time.Now().Format("2006-01-02 15:04:05")
	result.Pid = pid

	e.cacheMu.Lock()
	e.netCache[code] = &netCacheEntry{result: result, fetchedAt: time.Now()}
	e.cacheMu.Unlock()
	return result, nil
}

// fetchNetStats 查询进程树的端口和连接信息
func fetchNetStats(rootPid int) (*wafappmodel.NetStatsResult, error) {
	pids := getDescendantPIDs(rootPid)
	pidSet := make(map[int]bool, len(pids))
	for _, p := range pids {
		pidSet[p] = true
	}
	var result *wafappmodel.NetStatsResult
	var err error
	if runtime.GOOS == "windows" {
		result, err = fetchNetStatsWindows(pidSet)
	} else {
		result, err = fetchNetStatsLinux(pidSet)
	}
	if err != nil {
		return nil, err
	}
	result.Pids = pids
	return result, nil
}

// getDescendantPIDs BFS 遍历进程树，返回所有子孙 PID（含自身）
func getDescendantPIDs(rootPid int) []int {
	childMap := buildChildMap()
	var result []int
	queue := []int{rootPid}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		result = append(result, pid)
		queue = append(queue, childMap[pid]...)
	}
	if len(result) == 0 {
		result = []int{rootPid}
	}
	return result
}

// buildChildMap 构建 parentPID→[]childPID 映射
func buildChildMap() map[int][]int {
	m := make(map[int][]int)
	if runtime.GOOS == "windows" {
		buildChildMapWindows(m)
	} else {
		buildChildMapLinux(m)
	}
	return m
}

func buildChildMapWindows(m map[int][]int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 列名字母序：ParentProcessId 排在 ProcessId 前面
	out, err := wafexec.FixStdin(exec.CommandContext(ctx, "wmic", "process", "get", "ParentProcessId,ProcessId")).Output()
	if err != nil {
		return
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // 跳过表头
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ppid, e1 := strconv.Atoi(fields[0])
		pid, e2 := strconv.Atoi(fields[1])
		if e1 != nil || e2 != nil || pid == ppid || ppid == 0 {
			continue
		}
		m[ppid] = append(m[ppid], pid)
	}
}

func buildChildMapLinux(m map[int][]int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		for _, statusLine := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(statusLine, "PPid:") {
				ppid, _ := strconv.Atoi(strings.TrimSpace(statusLine[5:]))
				if ppid > 0 {
					m[ppid] = append(m[ppid], pid)
				}
				break
			}
		}
	}
}

func fetchNetStatsWindows(pidSet map[int]bool) (*wafappmodel.NetStatsResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := wafexec.FixStdin(exec.CommandContext(ctx, "netstat", "-ano")).Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var ports []wafappmodel.PortInfo
	var conns []wafappmodel.ConnInfo

	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		localAddr := fields[1]
		var state string
		var pid int

		switch proto {
		case "TCP":
			if len(fields) < 5 {
				continue
			}
			state = strings.ToUpper(fields[3])
			pid, _ = strconv.Atoi(fields[4])
		case "UDP":
			state = "LISTEN"
			pid, _ = strconv.Atoi(fields[3])
		default:
			continue
		}

		if pid == 0 || !pidSet[pid] {
			continue
		}
		port := parseNetPort(localAddr)

		switch state {
		case "LISTENING", "LISTEN":
			ports = append(ports, wafappmodel.PortInfo{
				Protocol: proto, LocalAddr: localAddr, Port: port, State: "LISTEN", Pid: pid,
			})
		case "ESTABLISHED":
			remoteAddr := fields[2]
			conns = append(conns, wafappmodel.ConnInfo{
				Protocol: proto, LocalAddr: localAddr, RemoteAddr: remoteAddr,
				RemoteIP: parseNetIP(remoteAddr), State: state, Pid: pid,
			})
		}
	}

	if ports == nil {
		ports = []wafappmodel.PortInfo{}
	}
	if conns == nil {
		conns = []wafappmodel.ConnInfo{}
	}
	return &wafappmodel.NetStatsResult{Ports: ports, Connections: conns}, nil
}

func fetchNetStatsLinux(pidSet map[int]bool) (*wafappmodel.NetStatsResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// ss -tanp: TCP all-states, numeric, with-process
	out, err := wafexec.FixStdin(exec.CommandContext(ctx, "ss", "-tanp")).Output()
	if err != nil {
		// 降级到 netstat
		return fetchNetStatsLinuxNetstat(pidSet)
	}
	return parseSSOutput(string(out), pidSet), nil
}

func parseSSOutput(data string, pidSet map[int]bool) *wafappmodel.NetStatsResult {
	pidRe := regexp.MustCompile(`pid=(\d+)`)
	var ports []wafappmodel.PortInfo
	var conns []wafappmodel.ConnInfo

	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // 跳过表头
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		state := strings.ToUpper(fields[0])
		localAddr := fields[3]
		peerAddr := fields[4]

		var pid int
		for j := 5; j < len(fields); j++ {
			if m := pidRe.FindStringSubmatch(fields[j]); m != nil {
				pid, _ = strconv.Atoi(m[1])
				break
			}
		}
		if pid == 0 || !pidSet[pid] {
			continue
		}
		port := parseNetPort(localAddr)

		switch state {
		case "LISTEN":
			ports = append(ports, wafappmodel.PortInfo{
				Protocol: "TCP", LocalAddr: localAddr, Port: port, State: "LISTEN", Pid: pid,
			})
		case "ESTAB", "ESTABLISHED":
			conns = append(conns, wafappmodel.ConnInfo{
				Protocol: "TCP", LocalAddr: localAddr, RemoteAddr: peerAddr,
				RemoteIP: parseNetIP(peerAddr), State: "ESTABLISHED", Pid: pid,
			})
		}
	}

	if ports == nil {
		ports = []wafappmodel.PortInfo{}
	}
	if conns == nil {
		conns = []wafappmodel.ConnInfo{}
	}
	return &wafappmodel.NetStatsResult{Ports: ports, Connections: conns}
}

func fetchNetStatsLinuxNetstat(pidSet map[int]bool) (*wafappmodel.NetStatsResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// netstat -tnap: TCP numeric all programs
	out, err := wafexec.FixStdin(exec.CommandContext(ctx, "netstat", "-tnap")).Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var ports []wafappmodel.PortInfo
	var conns []wafappmodel.ConnInfo

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i <= 1 {
			continue // 跳过两行表头
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Proto Recv-Q Send-Q Local Foreign State PID/prog
		if len(fields) < 7 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "tcp6" {
			continue
		}
		localAddr := fields[3]
		peerAddr := fields[4]
		state := strings.ToUpper(fields[5])
		pidProc := fields[6] // "1234/myapp" or "-"

		var pid int
		if parts := strings.SplitN(pidProc, "/", 2); len(parts) >= 1 {
			pid, _ = strconv.Atoi(parts[0])
		}
		if pid == 0 || !pidSet[pid] {
			continue
		}
		port := parseNetPort(localAddr)

		switch state {
		case "LISTEN":
			ports = append(ports, wafappmodel.PortInfo{
				Protocol: "TCP", LocalAddr: localAddr, Port: port, State: "LISTEN", Pid: pid,
			})
		case "ESTABLISHED":
			conns = append(conns, wafappmodel.ConnInfo{
				Protocol: "TCP", LocalAddr: localAddr, RemoteAddr: peerAddr,
				RemoteIP: parseNetIP(peerAddr), State: state, Pid: pid,
			})
		}
	}

	if ports == nil {
		ports = []wafappmodel.PortInfo{}
	}
	if conns == nil {
		conns = []wafappmodel.ConnInfo{}
	}
	return &wafappmodel.NetStatsResult{Ports: ports, Connections: conns}, nil
}

func parseNetPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return port
}

func parseNetIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
