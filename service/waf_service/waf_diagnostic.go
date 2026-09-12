package waf_service

import (
	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/model/response"
	"SamWaf/wafdb"
	"SamWaf/wafdiag"
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"time"

	"SamWaf/common/diagstat"
)

type WafDiagnosticService struct {
	mu            sync.Mutex
	lastSnapshot  response.WafDiagnosticSnapshot
	lastSnapAt    time.Time
	lastPackageAt time.Time
}

var WafDiagnosticServiceApp = new(WafDiagnosticService)

// 快照复用窗口与诊断包最小间隔：采集含 goroutine STW dump / 缓存全表遍历（拿全局锁）/
// runtime.GC 等操作，节流避免被脚本高频调用时与转发热路径争抢资源。
const (
	snapshotReuseWindow = 2 * time.Second
	packageMinInterval  = 10 * time.Second
)

var ErrPackageTooFrequent = errors.New("诊断包生成过于频繁，请稍后再试")

// GetSnapshot 返回运行诊断实时快照，2 秒窗口内复用上次结果。
func (receiver *WafDiagnosticService) GetSnapshot() response.WafDiagnosticSnapshot {
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	if !receiver.lastSnapAt.IsZero() && time.Since(receiver.lastSnapAt) < snapshotReuseWindow {
		return receiver.lastSnapshot
	}
	receiver.lastSnapshot = receiver.collectSnapshot()
	receiver.lastSnapAt = time.Now()
	return receiver.lastSnapshot
}

// collectSnapshot 组装快照：进程 + Go runtime + 组件计量 + 数据库体量。
func (receiver *WafDiagnosticService) collectSnapshot() response.WafDiagnosticSnapshot {
	snapshot := response.WafDiagnosticSnapshot{
		Version:    global.GWAF_RELEASE_VERSION,
		VersionTag: global.GWAF_RELEASE_VERSION_NAME,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Process:    wafdiag.CollectProcess(),
		Runtime:    wafdiag.CollectRuntime(),
		Components: diagstat.CollectAll(),
		SampledAt:  time.Now().Unix(),
	}
	if metricsList, err := wafdb.MonitorAllDatabases(); err == nil {
		for _, metrics := range metricsList {
			if metrics == nil {
				continue
			}
			snapshot.Databases = append(snapshot.Databases, response.WafDiagnosticDbInfo{
				Name:       metrics.DatabaseName,
				FileSizeMB: metrics.FileSizeMB,
			})
		}
	}
	return snapshot
}

// GetTrend 返回趋势采样数据。
func (receiver *WafDiagnosticService) GetTrend() response.WafDiagnosticTrend {
	return response.WafDiagnosticTrend{
		IntervalSec: 10,
		Points:      wafdiag.GetTrend(),
	}
}

// diagMeta 诊断包元信息。字段白名单制：只放定位性能问题需要的环境事实，
// 不含任何密钥、账号、请求体、站点域名类数据。
type diagMeta struct {
	Version    string `json:"version"`
	VersionTag string `json:"version_tag"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	GoVersion  string `json:"go_version"`
	GoMaxProcs int    `json:"gomaxprocs"`
	NumCPU     int    `json:"num_cpu"`
	DbDriver   string `json:"db_driver"`
	CacheType  string `json:"cache_type"`
	// 缓存后端形态与累计失败次数。后端不可用会表现为管理端频繁提示"服务暂时不可用"，
	// 这两项能一眼区分是缓存的问题还是业务的问题。
	CacheBackend   string `json:"cache_backend,omitempty"`
	CacheErrCount  uint64 `json:"cache_err_count,omitempty"`
	CacheLastErrAt string `json:"cache_last_err_at,omitempty"`
	CacheLastErr   string `json:"cache_last_err,omitempty"`
	GeneratedAt    string `json:"generated_at"`
}

// BuildDiagnosticPackage 把快照/趋势/goroutine dump/heap profile（以及已完成的
// CPU profile）在内存中组装成 zip 后整体返回，不落盘。
// 先组装后发送：组装期出错时调用方还能返回真实错误响应，而不是 200 + 截断的 zip。
// 最小间隔 10 秒：采集含 STW dump 与 runtime.GC，防高频调用影响转发性能。
func (receiver *WafDiagnosticService) BuildDiagnosticPackage() ([]byte, error) {
	receiver.mu.Lock()
	if !receiver.lastPackageAt.IsZero() && time.Since(receiver.lastPackageAt) < packageMinInterval {
		receiver.mu.Unlock()
		return nil, ErrPackageTooFrequent
	}
	receiver.lastPackageAt = time.Now()
	receiver.mu.Unlock()

	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)
	defer zipWriter.Close()

	writeFile := func(name string, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		f, err := zipWriter.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}

	meta := diagMeta{
		Version:     global.GWAF_RELEASE_VERSION,
		VersionTag:  global.GWAF_RELEASE_VERSION_NAME,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		GoMaxProcs:  runtime.GOMAXPROCS(0),
		NumCPU:      runtime.NumCPU(),
		DbDriver:    global.GWAF_DB_DRIVER,
		CacheType:   global.GCACHE_TYPE,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
	if stater, ok := global.GCACHE_WAFCACHE.(cache.BackendStater); ok {
		st := stater.BackendStats()
		meta.CacheBackend = st.Backend
		meta.CacheErrCount = st.ErrCount
		meta.CacheLastErr = st.LastErr
		if !st.LastErrAt.IsZero() {
			meta.CacheLastErrAt = st.LastErrAt.Format("2006-01-02 15:04:05")
		}
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeFile("meta.json", metaJSON); err != nil {
		return nil, err
	}

	snapshotJSON, _ := json.MarshalIndent(receiver.GetSnapshot(), "", "  ")
	if err := writeFile("snapshot.json", snapshotJSON); err != nil {
		return nil, err
	}

	trendJSON, _ := json.MarshalIndent(receiver.GetTrend(), "", "  ")
	if err := writeFile("trend.json", trendJSON); err != nil {
		return nil, err
	}

	if err := writeFile("goroutine_agg.txt", wafdiag.GoroutineDump(1)); err != nil {
		return nil, err
	}
	if err := writeFile("goroutine_full.txt", wafdiag.GoroutineDump(2)); err != nil {
		return nil, err
	}

	if heapData, err := wafdiag.HeapProfile(); err == nil {
		if err := writeFile("heap.pb.gz", heapData); err != nil {
			return nil, err
		}
	}

	if cpuData, finishedAt := wafdiag.CPUProfileResult(); len(cpuData) > 0 {
		if err := writeFile("cpu.pb.gz", cpuData); err != nil {
			return nil, err
		}
		note := "CPU profile 采样完成时间: " + finishedAt.Format("2006-01-02 15:04:05")
		if err := writeFile("cpu_profile_time.txt", []byte(note)); err != nil {
			return nil, err
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
