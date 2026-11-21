package wafdiag

import (
	"SamWaf/common/diagstat"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/wafenginecore/wafwebcache"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// 运行诊断数据采集：本进程视角（区别于 waf_system_monitor 的整机视角）。
// 所有采集都是内存/系统调用级别，毫秒内完成，可在生产环境随时调用。

var (
	selfProc  *process.Process
	startTime = time.Now()
)

func init() {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err == nil {
		selfProc = p
	}
}

// ProcessStat 本进程资源占用。
type ProcessStat struct {
	Pid           int32   `json:"pid"`
	CPUPercent    float64 `json:"cpu_percent"`     // 本进程 CPU 使用率（相对全机 100%）
	RSSBytes      uint64  `json:"rss_bytes"`       // 常驻内存
	VMSBytes      uint64  `json:"vms_bytes"`       // 虚拟内存
	NumThreads    int32   `json:"num_threads"`     // 线程数
	NumFDs        int32   `json:"num_fds"`         // 打开文件句柄数（Windows 下可能为 -1 表示不支持）
	UptimeSeconds int64   `json:"uptime_seconds"`  // 本进程运行时长
	StartTimeUnix int64   `json:"start_time_unix"` // 启动时间戳
}

// RuntimeStat Go 运行时内存/GC 视角。
type RuntimeStat struct {
	Goroutines     int    `json:"goroutines"`
	GoMaxProcs     int    `json:"gomaxprocs"`
	NumCPU         int    `json:"num_cpu"`
	HeapAlloc      uint64 `json:"heap_alloc"`     // 活对象占用
	HeapSys        uint64 `json:"heap_sys"`       // 堆向 OS 申请
	HeapInuse      uint64 `json:"heap_inuse"`     // 堆使用中 span
	HeapIdle       uint64 `json:"heap_idle"`      // 堆空闲 span（可归还 OS）
	HeapReleased   uint64 `json:"heap_released"`  // 已归还 OS
	StackInuse     uint64 `json:"stack_inuse"`    // goroutine 栈占用
	Sys            uint64 `json:"sys"`            // Go 向 OS 申请总量（与 RSS 的差值≈CGO/C 侧内存）
	NumGC          uint32 `json:"num_gc"`         // GC 次数
	LastGCUnix     int64  `json:"last_gc_unix"`   // 上次 GC 时间戳
	PauseTotalMs   uint64 `json:"pause_total_ms"` // GC 累计暂停
	NextGC         uint64 `json:"next_gc"`        // 下次 GC 触发阈值
	GoVersion      string `json:"go_version"`
	TotalAllocated uint64 `json:"total_allocated"` // 进程生命周期累计分配
}

// CollectProcess 采集本进程资源占用。CPU% 优先取趋势采样器缓存的最近值
// （与采样器共用同一 Process 对象时各自调用 Percent 会互相干扰采样窗口）。
func CollectProcess() ProcessStat {
	stat := ProcessStat{Pid: int32(os.Getpid()), NumFDs: -1}
	stat.StartTimeUnix = startTime.Unix()
	stat.UptimeSeconds = int64(time.Since(startTime).Seconds())
	stat.CPUPercent = LatestProcessCPU()
	if selfProc == nil {
		return stat
	}
	if memInfo, err := selfProc.MemoryInfo(); err == nil && memInfo != nil {
		stat.RSSBytes = memInfo.RSS
		stat.VMSBytes = memInfo.VMS
	}
	if threads, err := selfProc.NumThreads(); err == nil {
		stat.NumThreads = threads
	}
	if fds, err := selfProc.NumFDs(); err == nil {
		stat.NumFDs = fds
	}
	return stat
}

// CollectRuntime 采集 Go 运行时状态。
func CollectRuntime() RuntimeStat {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return RuntimeStat{
		Goroutines:     runtime.NumGoroutine(),
		GoMaxProcs:     runtime.GOMAXPROCS(0),
		NumCPU:         runtime.NumCPU(),
		HeapAlloc:      m.HeapAlloc,
		HeapSys:        m.HeapSys,
		HeapInuse:      m.HeapInuse,
		HeapIdle:       m.HeapIdle,
		HeapReleased:   m.HeapReleased,
		StackInuse:     m.StackInuse,
		Sys:            m.Sys,
		NumGC:          m.NumGC,
		LastGCUnix:     int64(m.LastGC / 1e9),
		PauseTotalMs:   m.PauseTotalNs / 1e6,
		NextGC:         m.NextGC,
		GoVersion:      runtime.Version(),
		TotalAllocated: m.TotalAlloc,
	}
}

// RegisterBuiltins 注册基于 global 全局对象的组件计量器（队列/通道/缓存/WebSocket）。
// 引擎自身的计量由 wafenginecore 注册，避免本包 import 引擎。在 main 启动早期调用一次。
func RegisterBuiltins() {
	diagstat.Register("db_queue", collectQueues)
	diagstat.Register("chan", collectChans)
	diagstat.Register("cache", collectCache)
	// 与控制台 KV 的条目数分开，防止把网页正文配额和凭证状态计数混为一类。
	diagstat.Register("web_cache", wafwebcache.Snapshot)
	diagstat.Register("websocket", collectWebsocket)
}

func collectQueues() map[string]int64 {
	items := map[string]int64{}
	if global.GQEQUE_DB != nil {
		items["db"] = int64(global.GQEQUE_DB.Size())
	}
	if global.GQEQUE_UPDATE_DB != nil {
		items["db_update"] = int64(global.GQEQUE_UPDATE_DB.Size())
	}
	if global.GQEQUE_LOG_DB != nil {
		items["log"] = int64(global.GQEQUE_LOG_DB.Size())
	}
	if global.GQEQUE_STATS_DB != nil {
		items["stats"] = int64(global.GQEQUE_STATS_DB.Size())
	}
	if global.GQEQUE_STATS_UPDATE_DB != nil {
		items["stats_update"] = int64(global.GQEQUE_STATS_UPDATE_DB.Size())
	}
	if global.GQEQUE_MESSAGE_DB != nil {
		items["message"] = int64(global.GQEQUE_MESSAGE_DB.Size())
	}
	return items
}

func collectChans() map[string]int64 {
	return map[string]int64{
		"host_len":       int64(len(global.GWAF_CHAN_HOST)),
		"host_cap":       int64(cap(global.GWAF_CHAN_HOST)),
		"engine_len":     int64(len(global.GWAF_CHAN_ENGINE)),
		"msg_len":        int64(len(global.GWAF_CHAN_MSG)),
		"common_msg_len": int64(len(global.GWAF_CHAN_COMMON_MSG)),
		"ssl_len":        int64(len(global.GWAF_CHAN_SSL)),
		"ssl_order_len":  int64(len(global.GWAF_CHAN_SSLOrder)),
		"task_len":       int64(len(global.GWAF_CHAN_TASK)),
	}
}

// collectCache 缓存条目计量：一次 ListAvailableKeys 遍历，按关心的前缀分类计数。
// 仅在快照请求时执行（不进 10s 趋势采样），条目多时的一次拷贝可以接受。
func collectCache() map[string]int64 {
	if global.GCACHE_WAFCACHE == nil {
		return nil
	}
	keys := global.GCACHE_WAFCACHE.ListAvailableKeys()
	items := map[string]int64{"total": int64(len(keys))}
	prefixes := map[string]string{
		"cc_ban":       enums.CACHE_CCVISITBAN_PRE,
		"replay_nonce": enums.CACHE_REPLAY_NONCE,
		"ip_failure":   enums.CACHE_IP_FAILURE_PRE,
		"access":       "CACHE_ACCESS_",
	}
	for key := range keys {
		for name, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				items[name]++
			}
		}
	}
	return items
}

func collectWebsocket() map[string]int64 {
	if global.GWebSocket == nil {
		return nil
	}
	return map[string]int64{"online": int64(global.GWebSocket.OnlineCount())}
}
