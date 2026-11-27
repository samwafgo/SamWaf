package wafconfig

import (
	"SamWaf/global"
	"testing"

	"github.com/spf13/viper"
)

// TestPostgresCacheDefaultsAndValidation 校验有限默认预算、类型别名规范化和非法连接池拒绝。
func TestPostgresCacheDefaultsAndValidation(t *testing.T) {
	beforeType, beforeDB, beforeNS := global.GCACHE_TYPE, global.GCACHE_PG_DATABASE, global.GCACHE_PG_NAMESPACE
	beforePool, beforeTimeout, beforeCleanup, beforeMemory := global.GCACHE_PG_POOL_SIZE, global.GCACHE_PG_OP_TIMEOUT_SEC, global.GCACHE_PG_CLEANUP_SEC, global.GCACHE_WEB_L1_CAPACITY_MB
	t.Cleanup(func() {
		global.GCACHE_TYPE, global.GCACHE_PG_DATABASE, global.GCACHE_PG_NAMESPACE = beforeType, beforeDB, beforeNS
		global.GCACHE_PG_POOL_SIZE, global.GCACHE_PG_OP_TIMEOUT_SEC, global.GCACHE_PG_CLEANUP_SEC, global.GCACHE_WEB_L1_CAPACITY_MB = beforePool, beforeTimeout, beforeCleanup, beforeMemory
	})
	c := viper.New()
	if err := loadPostgresCacheConfig(c); err != nil {
		t.Fatal(err)
	}
	if global.GCACHE_TYPE != "postgres" || global.GCACHE_PG_DATABASE != "samwaf_cache" || global.GCACHE_WEB_L1_CAPACITY_MB != 256 {
		t.Fatal("unexpected PostgreSQL cache defaults")
	}
	c.Set("cache.type", "PGSQL")
	if err := loadPostgresCacheConfig(c); err != nil || c.GetString("cache.type") != "postgres" {
		t.Fatal("cache type alias was not normalized")
	}
	c.Set("cache.postgres.pool_size", 0)
	if err := loadPostgresCacheConfig(c); err == nil {
		t.Fatal("invalid connection pool accepted")
	}
}

// TestPostgresEnvironmentDoesNotPersistPassword 校验环境值只覆盖连接状态，以及非法端口不能继续使用。
func TestPostgresEnvironmentDoesNotPersistPassword(t *testing.T) {
	oldHost, oldPassword, oldPort := global.GWAF_PG_HOST, global.GWAF_PG_PASSWORD, global.GWAF_PG_PORT
	t.Cleanup(func() {
		global.GWAF_PG_HOST, global.GWAF_PG_PASSWORD, global.GWAF_PG_PORT = oldHost, oldPassword, oldPort
	})
	t.Setenv("SAMWAF_PG_HOST", "localhost")
	t.Setenv("SAMWAF_PG_PORT", "5433")
	t.Setenv("SAMWAF_PG_PASSWORD", "synthetic-config-secret")
	if err := postgresEnvironment(); err != nil {
		t.Fatal(err)
	}
	if global.GWAF_PG_HOST != "localhost" || global.GWAF_PG_PORT != 5433 || global.GWAF_PG_PASSWORD != "synthetic-config-secret" {
		t.Fatal("environment overrides were ignored")
	}
	t.Setenv("SAMWAF_PG_PORT", "invalid")
	if err := postgresEnvironment(); err == nil {
		t.Fatal("invalid environment port accepted")
	}
}
