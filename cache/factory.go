package cache

import (
	"fmt"
	"time"
)

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

// NewCacheStore 按类型创建业务状态后端；正常 Worker 的默认及必选类型是 postgres。
// PostgreSQL/Redis 初始化失败必须返回错误，不能静默切内存造成凭据和封禁状态丢失。
// postgresCfg 使用可变参数保留旧调用签名；memory 和空类型仅延续旧适配器/测试的行为。
func NewCacheStore(cacheType string, redisCfg *RedisCacheConfig, postgresCfg ...*PostgresCacheConfig) (CacheStore, error) {
	if cacheType == "postgres" {
		if len(postgresCfg) == 0 {
			return nil, fmt.Errorf("PostgreSQL cache configuration is required")
		}
		return NewPostgresCache(postgresCfg[0])
	}
	if cacheType == "redis" && redisCfg != nil {
		rc, err := NewRedisCache(redisCfg)
		if err != nil {
			return nil, err
		}
		return rc, nil
	}
	if cacheType == "memory" || cacheType == "" {
		return InitWafCache(), nil
	}
	return nil, fmt.Errorf("unsupported cache backend %q", cacheType)
}
