package cache

// RedisCacheConfig Redis连接配置
type RedisCacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
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
