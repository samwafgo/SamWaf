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
func NewCacheStore(cacheType string, redisCfg *RedisCacheConfig) CacheStore {
	if cacheType == "redis" && redisCfg != nil {
		return NewRedisCache(redisCfg)
	}
	return InitWafCache()
}
