package wafconfig

import (
	"SamWaf/global"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// loadPostgresCacheConfig 为控制台 KV 和进程 L1 配额补有限默认值，并验证连接数/时间/容量范围。
// 缓存后端别名写回 Viper 的内存配置，避免后续兼容读取再次覆盖已规范化的类型。
func loadPostgresCacheConfig(config *viper.Viper) error {
	config.SetDefault("cache.type", "postgres")
	config.SetDefault("cache.postgres.database", "samwaf_cache")
	config.SetDefault("cache.postgres.namespace", "samwaf")
	config.SetDefault("cache.postgres.pool_size", 32)
	config.SetDefault("cache.postgres.op_timeout_seconds", 5)
	config.SetDefault("cache.postgres.cleanup_seconds", 60)
	config.SetDefault("web_cache.l1_capacity_mb", 256)
	global.GCACHE_TYPE = strings.ToLower(strings.TrimSpace(config.GetString("cache.type")))
	if global.GCACHE_TYPE == "pgsql" || global.GCACHE_TYPE == "postgresql" {
		global.GCACHE_TYPE = "postgres"
	}
	config.Set("cache.type", global.GCACHE_TYPE)
	global.GCACHE_PG_DATABASE = config.GetString("cache.postgres.database")
	global.GCACHE_PG_NAMESPACE = config.GetString("cache.postgres.namespace")
	global.GCACHE_PG_POOL_SIZE = config.GetInt("cache.postgres.pool_size")
	global.GCACHE_PG_OP_TIMEOUT_SEC = config.GetInt("cache.postgres.op_timeout_seconds")
	global.GCACHE_PG_CLEANUP_SEC = config.GetInt("cache.postgres.cleanup_seconds")
	global.GCACHE_WEB_L1_CAPACITY_MB = config.GetInt64("web_cache.l1_capacity_mb")
	if global.GCACHE_PG_POOL_SIZE < 1 || global.GCACHE_PG_POOL_SIZE > 1024 {
		return fmt.Errorf("cache.postgres.pool_size must be between 1 and 1024")
	}
	if global.GCACHE_PG_OP_TIMEOUT_SEC < 1 || global.GCACHE_PG_OP_TIMEOUT_SEC > 60 {
		return fmt.Errorf("cache.postgres.op_timeout_seconds must be between 1 and 60")
	}
	if global.GCACHE_PG_CLEANUP_SEC < 1 || global.GCACHE_PG_CLEANUP_SEC > 3600 {
		return fmt.Errorf("cache.postgres.cleanup_seconds must be between 1 and 3600")
	}
	if global.GCACHE_WEB_L1_CAPACITY_MB < 1 || global.GCACHE_WEB_L1_CAPACITY_MB > 65536 {
		return fmt.Errorf("web_cache.l1_capacity_mb must be between 1 and 65536")
	}
	return nil
}

// postgresEnvironment 只接受这里列出的环境变量覆盖，且不把环境口令写入 Viper 或配置文件。
// 它在文件配置读取完成后调用，让容器注入值优先于磁盘默认值。
func postgresEnvironment() error {
	fields := map[string]*string{
		"SAMWAF_PG_HOST": &global.GWAF_PG_HOST, "SAMWAF_PG_USER": &global.GWAF_PG_USER,
		"SAMWAF_PG_PASSWORD": &global.GWAF_PG_PASSWORD, "SAMWAF_PG_SSLMODE": &global.GWAF_PG_SSLMODE,
		"SAMWAF_PG_TIMEZONE": &global.GWAF_PG_TIMEZONE, "SAMWAF_PG_CORE_DB": &global.GWAF_PG_CORE_DB,
		"SAMWAF_PG_LOG_DB": &global.GWAF_PG_LOG_DB, "SAMWAF_PG_STATS_DB": &global.GWAF_PG_STATS_DB,
		"SAMWAF_PG_CACHE_DB": &global.GCACHE_PG_DATABASE,
	}
	for name, target := range fields {
		if value, ok := os.LookupEnv(name); ok {
			*target = value
		}
	}
	if value, ok := os.LookupEnv("SAMWAF_PG_PORT"); ok {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid SAMWAF_PG_PORT")
		}
		global.GWAF_PG_PORT = port
	}
	return nil
}
