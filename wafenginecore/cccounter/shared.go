package cccounter

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync/atomic"
)

// SharedStore 只约定计数操作，不依赖全局配置或具体数据库包。
type SharedStore interface {
	SecurityCount(string, string, string, int, int, int, int) (int64, bool, bool, bool, error)
	DropSecurityCounters(string) error
}

// sharedCounter 的统计只描述本 Worker 的调用，不把本地零键数冒充数据库全局键数。
type sharedCounter struct {
	store                               SharedStore
	calls, failures, degraded, rejected atomic.Int64
}

// UseSharedStore 在 Worker 初始化时接入共享后端；配置变化按窗口隔离，不互相清空旧 Worker 的计数。
func (c *Counter) UseSharedStore(store SharedStore) { c.shared.Store(&sharedCounter{store: store}) }

// incr 在数据库中原子累加，维度只保存 SHA256，不向后端暴露 Cookie/Token 等原文。
func (s *sharedCounter) incr(rule, dimension string, window int, maxKeys int64, quota int) Result {
	if len(dimension) > maxDimValueLen {
		dimension = dimension[:maxDimValueLen]
	}
	sum := sha256.Sum256([]byte(dimension))
	s.calls.Add(1)
	count, _, degraded, rejected, err := s.store.SecurityCount("cc|"+rule+"|"+strconv.Itoa(window), hex.EncodeToString(sum[:]), "buckets", window, 0, int(maxKeys), quota)
	if err != nil {
		s.failures.Add(1)
		return Result{BackendUnavailable: true}
	}
	if degraded {
		s.degraded.Add(1)
	}
	if rejected {
		s.rejected.Add(1)
	}
	return Result{Count: count, Degraded: degraded, Rejected: rejected}
}

// stats 不在运行诊断读取路径发起 SQL；共享键基数由数据库指标提供。
func (s *sharedCounter) stats(maxKeys int64, quota int) map[string]int64 {
	return map[string]int64{"shared_backend": 1, "max_keys": maxKeys, "rule_quota": int64(quota), "calls": s.calls.Load(), "backend_errors": s.failures.Load(), "degraded_count": s.degraded.Load(), "rejected_count": s.rejected.Load()}
}
