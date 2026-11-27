package cache

import (
	"context"
	"errors"
	"time"
)

// IsMiss 兼容测试适配器的未命中标记；后端连接/解码错误不能归为未命中。
func IsMiss(err error) bool {
	if errors.Is(err, ErrCacheMiss) {
		return true
	}
	marker, ok := err.(interface{ IsCacheMiss() bool })
	return ok && marker.IsCacheMiss()
}

// BatchExister 将同一请求所需的封禁状态合并为一次后端往返，并保留取消和故障语义。
type BatchExister interface {
	ExistsManyE(context.Context, []string) (map[string]bool, error)
}

// JSONUpdater 在后端事务内串行化同键的读取、修改、写回，供跨 Worker 的失败事件计数使用。
type JSONUpdater interface {
	UpdateJSONE(string, time.Duration, func([]byte) ([]byte, error)) error
}

// SecurityCounterStore 提供服务端原子计数，返回值显式区分阈值、配额与后端故障。
type SecurityCounterStore interface {
	SecurityCount(string, string, string, int, int, int, int) (int64, bool, bool, bool, error)
	DropSecurityCounters(string) error
}

// SecurityDeleter 返回实际删除故障，解封接口不能在后端不可用时报告成功。
type SecurityDeleter interface{ RemoveE(string) error }

// SecurityReleaser 在同一事务中删除封禁并清理该 IP 的共享 CC 计数，避免解封后被旧额度立即重封。
type SecurityReleaser interface{ ReleaseSecurityE([]string, string) error }

// ReleaseE 保留普通适配器兼容，正常 PostgreSQL 走事务化释放。
func ReleaseE(store CacheStore, keys []string, resetIP string) error {
	if strict, ok := store.(SecurityReleaser); ok {
		return strict.ReleaseSecurityE(keys, resetIP)
	}
	for _, key := range keys {
		if err := DeleteE(store, key); err != nil {
			return err
		}
	}
	return nil
}

// SecurityKeyLister 为管理操作保留后端故障，空列表不能代替查询失败。
type SecurityKeyLister interface {
	KeysWithPrefixE(string) (map[string]time.Duration, error)
}

// ExistsKeysE 对正常 PostgreSQL 使用批量查询；兼容适配器逐键读取时也必须传播错误。
func ExistsKeysE(ctx context.Context, store CacheStore, keys []string) (map[string]bool, error) {
	if store == nil {
		return nil, ErrCacheBackend
	}
	if batch, ok := store.(BatchExister); ok {
		return batch.ExistsManyE(ctx, keys)
	}
	result := make(map[string]bool, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		exists, err := store.ExistsE(key)
		if err != nil {
			return nil, err
		}
		result[key] = exists
	}
	return result, nil
}

// AddOnceE 原子写入固定封禁期；已存在的封禁不会因并发触发而重新获得 TTL。
func AddOnceE(store CacheStore, key string, value interface{}, ttl time.Duration) (bool, error) {
	if store == nil {
		return false, ErrCacheBackend
	}
	if atomic, ok := store.(AtomicAdder); ok {
		return atomic.AddWithTTL(key, value, ttl)
	}
	// 这里只兼容旧测试适配器；正常 Worker 要求 PostgreSQL，始终走上面的原子路径。
	exists, err := store.ExistsE(key)
	if err != nil || exists {
		return false, err
	}
	store.SetWithTTl(key, value, ttl)
	return true, nil
}

// DeleteE 在安全状态管理路径中显式传播后端删除错误。
func DeleteE(store CacheStore, key string) error {
	if store == nil {
		return ErrCacheBackend
	}
	if strict, ok := store.(SecurityDeleter); ok {
		return strict.RemoveE(key)
	}
	store.Remove(key)
	return nil
}

// KeysE 仅在旧适配器中使用兼容列表接口，正常后端明确返回查询错误。
func KeysE(store CacheStore, prefix string) (map[string]time.Duration, error) {
	if store == nil {
		return nil, ErrCacheBackend
	}
	if strict, ok := store.(SecurityKeyLister); ok {
		return strict.KeysWithPrefixE(prefix)
	}
	return store.ListAvailableKeysWithPrefix(prefix), nil
}
