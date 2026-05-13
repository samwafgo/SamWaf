package cache

import "time"

// CacheStore 缓存后端接口，支持内存、Redis 等多种实现
type CacheStore interface {
	Set(key string, value interface{})
	SetWithTTl(key string, value interface{}, ttl time.Duration)
	SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration)
	Get(key string) interface{}
	// GetAs 将缓存值反序列化到 out（out 必须为指针）。
	// 对于 Redis 等非内存后端，Get() 返回的是 map[string]interface{}，
	// 无法直接类型断言为具体 struct；应使用 GetAs 代替。
	GetAs(key string, out interface{}) error
	GetBytes(key string) ([]byte, error)
	GetString(key string) (string, error)
	GetInt(key string) (int, error)
	IsKeyExist(key string) bool
	Remove(key string) interface{}
	GetExpireTime(key string) (time.Time, error)
	ListAvailableKeys() map[string]time.Duration
	ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration
}
