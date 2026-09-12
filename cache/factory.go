package cache

import "time"

// RedisCacheConfig Redis连接配置
type RedisCacheConfig struct {
	Host     string
	Password string
	Port     int
	DB       int
	// PoolSize 连接池大小，<=0 时用 go-redis 默认值(10 × GOMAXPROCS)
	PoolSize int
	// PoolTimeout 等待空闲连接的上限，<=0 时用 go-redis 默认值(ReadTimeout + 1s)
	PoolTimeout time.Duration
	// OpTimeout 单次操作总上限，<=0 时用 defaultRedisOpTimeout
	OpTimeout time.Duration
}

// NewCacheStore 根据cacheType创建缓存实例
// cacheType: "memory"（默认）| "redis"
// 当 cacheType 为 "redis" 但 Redis 不可达时返回 error
func NewCacheStore(cacheType string, redisCfg *RedisCacheConfig) (CacheStore, error) {
	if cacheType == "redis" && redisCfg != nil {
		rc, err := NewRedisCache(redisCfg)
		if err != nil {
			return nil, err
		}
		return rc, nil
	}
	return InitWafCache(), nil
}
