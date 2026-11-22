package cache

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"SamWaf/common/zlog"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// postgresCacheDDL 与服务器扩展使用同一份 SQL；托管 PostgreSQL 无法安装扩展文件时直接安装相同 schema。
//
//go:embed postgres/samwaf_kv--1.0.sql
var postgresCacheDDL string

// PostgresCacheConfig 配置控制台/业务状态的独立 KV 后端，不保存网站响应正文。
type PostgresCacheConfig struct {
	DSN             string        // 数据库连接串，可能含口令，不得写入日志或诊断结果。
	Namespace       string        // 实例隔离前缀，最长 256 字节；同一实例滚动重启保持相同值。
	PoolSize        int           // 最大连接数，非正值使用 32；不是缓存条目或容量限制。
	OpTimeout       time.Duration // 单次操作及一次后台清理预算，非正值默认 5 秒。
	CleanupInterval time.Duration // 空间回收周期，非正值默认 1 分钟；不决定过期数据可见性。
}

// PostgresCache 使用持久 PostgreSQL 表实现 CacheStore，读取时由数据库即时判断 TTL。
// db 可并发使用，错误诊断由 errMu 保护；cancel/done/once 管理后台清理的关闭生命周期。
type PostgresCache struct {
	db        *sql.DB
	namespace string
	timeout   time.Duration
	cancel    context.CancelFunc
	done      chan struct{}
	once      sync.Once
	errMu     sync.Mutex
	errors    BackendStats
	lastLog   time.Time
}

// 编译期检查适配器方法齐全，避免新增接口方法后运行时才暴露缺失。
var _ CacheStore = (*PostgresCache)(nil)

// NewPostgresCache 校验配置、连接和 KV schema 后才启动清理协程；失败不会降级到内存。
// 返回的实例由调用方 Close，连接池应在业务连接排空后关闭。
func NewPostgresCache(cfg *PostgresCacheConfig) (*PostgresCache, error) {
	if cfg == nil || cfg.DSN == "" {
		return nil, errors.New("PostgreSQL cache DSN is required")
	}
	namespace := cfg.Namespace
	if namespace == "" {
		namespace = "samwaf"
	}
	if len(namespace) > 256 || strings.ContainsRune(namespace, 0) {
		return nil, errors.New("invalid PostgreSQL cache namespace")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL cache connection configuration")
	}
	pool := cfg.PoolSize
	if pool <= 0 {
		pool = 32
	}
	db.SetMaxOpenConns(pool)
	db.SetMaxIdleConns(pool / 2)
	db.SetConnMaxIdleTime(3 * time.Minute)
	db.SetConnMaxLifetime(time.Hour)
	timeout := cfg.OpTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("PostgreSQL cache unavailable (%s)", safePGError(err))
	}
	if err := installPostgresKV(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("PostgreSQL KV/TTL initialization failed (%s)", safePGError(err))
	}
	var healthy bool
	if err := db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_exists($1,'__samwaf_startup_probe__')", namespace).Scan(&healthy); err != nil {
		db.Close()
		return nil, fmt.Errorf("PostgreSQL KV/TTL validation failed (%s)", safePGError(err))
	}
	lifetime, stop := context.WithCancel(context.Background())
	p := &PostgresCache{db: db, namespace: namespace, timeout: timeout, cancel: stop, done: make(chan struct{}), errors: BackendStats{Backend: "postgres"}}
	interval := cfg.CleanupInterval
	if interval <= 0 {
		interval = time.Minute
	}
	go p.cleanupLoop(lifetime, interval)
	return p, nil
}

// installPostgresKV 用事务咨询锁串行化多 Worker 的首次安装，安装失败会整体回滚。
// 可用时注册 samwaf_kv 扩展，否则安装嵌入的同源 SQL；已有安装只接受当前版本。
func installPostgresKV(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(7357140142)"); err != nil {
		return err
	}
	var installed bool
	if err = tx.QueryRowContext(ctx, "SELECT to_regprocedure('samwaf_kv.version()') IS NOT NULL").Scan(&installed); err != nil {
		return err
	}
	if installed {
		var version int
		if err = tx.QueryRowContext(ctx, "SELECT samwaf_kv.version()").Scan(&version); err != nil {
			return err
		}
		if version != 1 {
			return errors.New("unsupported KV schema version")
		}
	} else {
		var available bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_available_extensions WHERE name='samwaf_kv')").Scan(&available); err != nil {
			return err
		}
		if available {
			_, err = tx.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS samwaf_kv")
		} else {
			_, err = tx.ExecContext(ctx, postgresCacheDDL)
		}
		if err != nil {
			return err
		}
	}
	// 新的安全计数 schema 由应用角色持有；已有 KV v1 安装也可独立补齐，无需改超级用户对象。
	var securityInstalled bool
	if err = tx.QueryRowContext(ctx, "SELECT to_regprocedure('samwaf_security.version()') IS NOT NULL").Scan(&securityInstalled); err != nil {
		return err
	}
	if !securityInstalled {
		if _, err = tx.ExecContext(ctx, securityDDL); err != nil {
			return err
		}
	} else {
		var version int
		if err = tx.QueryRowContext(ctx, "SELECT samwaf_security.version()").Scan(&version); err != nil {
			return err
		}
		if version != 1 {
			return errors.New("unsupported security counter schema version")
		}
	}
	return tx.Commit()
}

// safePGError 只输出取消/超时、SQLSTATE 或错误类型；底层错误文本可能含 DSN、参数和凭据。
func safePGError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "SQLSTATE " + pgErr.Code
	}
	// 非 PostgreSQL 错误也只保留类型，不能直接格式化 err 的完整内容。
	return fmt.Sprintf("%T", err)
}

// note 区分真正未命中与后端故障，并对后者计数、脱敏和限频记录。
// 调用方 op 必须是固定操作名，不能把缓存键作为操作名传入。
func (p *PostgresCache) note(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCacheMiss
	}
	message := op + ": " + safePGError(err)
	now := time.Now()
	p.errMu.Lock()
	p.errors.ErrCount++
	p.errors.LastErrAt = now
	p.errors.LastErr = message
	log := now.Sub(p.lastLog) >= 10*time.Second
	if log {
		p.lastLog = now
	}
	p.errMu.Unlock()
	if log {
		zlog.Error("PostgreSQL cache operation failed", message)
	}
	return fmt.Errorf("%w: %s", ErrCacheBackend, message)
}

// op 为同步 CacheStore 接口提供独立超时；调用方必须 cancel 释放定时器。
func (p *PostgresCache) op() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout)
}

// ttlMS 转换为 SQL 接口使用的毫秒；正但不足 1 毫秒的 TTL 向上取到 1，非正值保留为 0。
func ttlMS(ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	ms := ttl.Milliseconds()
	if ms == 0 {
		return 1
	}
	return ms
}

// Set 兼容长效写入，使用有限的 100 年 TTL，实际删除仍可随时执行。
func (p *PostgresCache) Set(key string, value interface{}) {
	p.SetWithTTl(key, value, 100*365*24*time.Hour)
}

// SetWithTTl 将值序列化为 JSONB，以当前时间重置 TTL；ttl<=0 删除该键。
// 旧接口没有错误返回，编码/后端失败通过 BackendStats 和脱敏日志暴露。
func (p *PostgresCache) SetWithTTl(key string, value interface{}, ttl time.Duration) {
	b, err := json.Marshal(value)
	if err != nil {
		p.note("encode", err)
		return
	}
	ctx, cancel := p.op()
	defer cancel()
	_, err = p.db.ExecContext(ctx, "SELECT samwaf_kv.kv_set($1,$2,$3::jsonb,$4)", p.namespace, key, string(b), ttlMS(ttl))
	p.note("set", err)
}

// SetWithTTlRenewTime 与 PostgreSQL SET TTL 语义一致，续期从本次写入时刻开始。
func (p *PostgresCache) SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration) {
	p.SetWithTTl(key, value, ttl)
}

// read 统一读取原始 JSON；正 TTL 使用一条 GETEX 原子完成读取和续期。
// SQL 函数返回 NULL 表示未命中/已过期，不能把它误判为数据库连接故障。
func (p *PostgresCache) read(key string, ttl time.Duration) ([]byte, error) {
	ctx, cancel := p.op()
	defer cancel()
	var value []byte
	var err error
	if ttl > 0 {
		err = p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_getex($1,$2,$3)", p.namespace, key, ttlMS(ttl)).Scan(&value)
	} else {
		err = p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_get($1,$2)", p.namespace, key).Scan(&value)
	}
	if err != nil {
		return nil, p.note("get", err)
	}
	if len(value) == 0 {
		return nil, ErrCacheMiss
	}
	return value, nil
}

// Get 保留泛型 JSON 值语义；未命中或后端故障均返回 nil。
// 安全判定及结构体读取应使用 GetAs/GetAsEx，以保留错误分类并避免 map 到结构体的断言失败。
func (p *PostgresCache) Get(key string) interface{} {
	b, err := p.read(key, 0)
	if err != nil {
		return nil
	}
	var out interface{}
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// GetAs 把 JSON 还原到 out 指针，透传未命中、后端故障或类型不匹配错误，不改变 TTL。
func (p *PostgresCache) GetAs(key string, out interface{}) error {
	b, err := p.read(key, 0)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// GetAsEx 读取并原子续期；ttl<=0 时仅查询，不续期也不删除。
func (p *PostgresCache) GetAsEx(key string, out interface{}, ttl time.Duration) error {
	b, err := p.read(key, ttl)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// GetBytes 还原 Go JSON 编码为 Base64 字符串的原始字节，调用者仍须检查 error。
func (p *PostgresCache) GetBytes(key string) ([]byte, error) {
	var out []byte
	err := p.GetAs(key, &out)
	return out, err
}

// GetString 按字符串读取，不将其他 JSON 类型强制转成文本。
func (p *PostgresCache) GetString(key string) (string, error) {
	var out string
	err := p.GetAs(key, &out)
	return out, err
}

// GetInt 按 JSON 解码规则填充 Go int；调用者不能忽略读取/解码错误，把零值当作有效计数。
func (p *PostgresCache) GetInt(key string) (int, error) {
	var out int
	err := p.GetAs(key, &out)
	return out, err
}

// Touch 只续期现存且未过期的键；非正 TTL 只检查存在性，缺失返回 ErrCacheMiss。
func (p *PostgresCache) Touch(key string, ttl time.Duration) error {
	ctx, cancel := p.op()
	defer cancel()
	var exists bool
	err := p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_touch($1,$2,$3)", p.namespace, key, ttlMS(ttl)).Scan(&exists)
	if err != nil {
		return p.note("touch", err)
	}
	if !exists {
		return ErrCacheMiss
	}
	return nil
}

// IsKeyExist 兼容旧接口，故障也按 false 返回；需要故障时拒绝放行的路径必须使用 ExistsE。
func (p *PostgresCache) IsKeyExist(key string) bool { ok, _ := p.ExistsE(key); return ok }

// ExistsE 使用数据库时钟检查未到期键，并单独返回后端故障。
func (p *PostgresCache) ExistsE(key string) (bool, error) {
	ctx, cancel := p.op()
	defer cancel()
	var exists bool
	err := p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_exists($1,$2)", p.namespace, key).Scan(&exists)
	if err != nil {
		return false, p.note("exists", err)
	}
	return exists, nil
}

// Remove 幂等删除键；沿用旧接口返回 nil，后端删除失败会记录到 BackendStats。
func (p *PostgresCache) Remove(key string) interface{} {
	_ = p.RemoveE(key)
	return nil
}

// GetExpireTime 返回数据库保存的绝对到期时刻，缺失或已过期时返回 ErrCacheMiss。
func (p *PostgresCache) GetExpireTime(key string) (time.Time, error) {
	ctx, cancel := p.op()
	defer cancel()
	var expires sql.NullTime
	err := p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_expires($1,$2)", p.namespace, key).Scan(&expires)
	if err != nil {
		return time.Time{}, p.note("expires", err)
	}
	if !expires.Valid {
		return time.Time{}, ErrCacheMiss
	}
	return expires.Time, nil
}

// ListAvailableKeys 枚举当前 namespace 的全部可用键，供管理/诊断按需调用。
func (p *PostgresCache) ListAvailableKeys() map[string]time.Duration {
	return p.ListAvailableKeysWithPrefix("")
}

// ListAvailableKeysWithPrefix 在一次查询中返回字面前缀匹配的键和绝对到期时间。
// %/_ 不作为 SQL 通配符；剩余时长由本机估算，真正可见性仍由数据库时钟决定。
func (p *PostgresCache) ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration {
	result, _ := p.KeysWithPrefixE(prefix)
	return result
}

// KeysWithPrefixE 返回枚举故障，供解封/安全状态列表使用；兼容接口的错误统计仍由 note 记录。
func (p *PostgresCache) KeysWithPrefixE(prefix string) (map[string]time.Duration, error) {
	result := map[string]time.Duration{}
	ctx, cancel := p.op()
	defer cancel()
	rows, err := p.db.QueryContext(ctx, "SELECT cache_key,expires_at FROM samwaf_kv.kv_keys($1,$2)", p.namespace, prefix)
	if err != nil {
		return result, p.note("keys", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var expires time.Time
		if err := rows.Scan(&key, &expires); err != nil {
			return result, p.note("keys", err)
		}
		if ttl := time.Until(expires); ttl > 0 {
			result[key] = ttl
		}
	}
	return result, p.note("keys", rows.Err())
}

// AddWithTTL 通过条件 UPSERT 实现原子「不存在才写入」，已过期键可重新占用。
// 同键并发仅允许一个成功，用于防重放 nonce；后端故障不能等价为允许首次写入。
func (p *PostgresCache) AddWithTTL(key string, value interface{}, ttl time.Duration) (bool, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	ctx, cancel := p.op()
	defer cancel()
	var added bool
	err = p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_add($1,$2,$3::jsonb,$4)", p.namespace, key, string(b), ttlMS(ttl)).Scan(&added)
	if err != nil {
		return false, p.note("add", err)
	}
	return added, nil
}

// IncrementWithTTL 在数据库内原子累加，避免跨 Worker 的读改写丢计数。
// renew=false 保持固定窗口；true 重置期限；过期或缺失键从 delta 重新开始。
func (p *PostgresCache) IncrementWithTTL(key string, delta int64, ttl time.Duration, renew bool) (int64, error) {
	ctx, cancel := p.op()
	defer cancel()
	var value int64
	err := p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_incrby($1,$2,$3,$4,$5)", p.namespace, key, delta, ttlMS(ttl), renew).Scan(&value)
	if err != nil {
		return 0, p.note("incr", err)
	}
	return value, nil
}

// CleanupExpired 在独立超时内清理一批最多 5000 条过期记录，不删除未到期状态。
func (p *PostgresCache) CleanupExpired() (int64, error) {
	ctx, cancel := p.op()
	defer cancel()
	return p.cleanupContext(ctx)
}

// cleanupContext 让后台多批清理共用同一取消/超时预算；SQL 使用 SKIP LOCKED 避免等业务行锁。
func (p *PostgresCache) cleanupContext(ctx context.Context) (int64, error) {
	var removed int64
	err := p.db.QueryRowContext(ctx, "SELECT samwaf_kv.kv_cleanup(5000)").Scan(&removed)
	if err != nil {
		return 0, p.note("cleanup", err)
	}
	// 空间回收不改变有效窗口，其他 Worker 正在写的键由 SQL 的 SKIP LOCKED 避开。
	var securityRemoved int64
	if err = p.db.QueryRowContext(ctx, "SELECT samwaf_security.cleanup($1,NULL,5000)", p.namespace).Scan(&securityRemoved); err != nil {
		return removed, p.note("security_cleanup", err)
	}
	removed += securityRemoved
	return removed, nil
}

// cleanupLoop 每个周期最多处理 64 批，所有批次共用一次操作预算，防止积压清理长期占池。
// 过期判断在读取时即时执行；这个协程只回收空间，并随实例关闭取消。
func (p *PostgresCache) cleanupLoop(ctx context.Context, interval time.Duration) {
	defer close(p.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			budget, cancel := context.WithTimeout(ctx, p.timeout)
			for batch := 0; batch < 64; batch++ {
				removed, err := p.cleanupContext(budget)
				if err != nil || removed < 5000 {
					break
				}
			}
			cancel()
		}
	}
}

// BackendStats 在锁内复制脱敏错误快照，不返回键、值或连接串。
func (p *PostgresCache) BackendStats() BackendStats {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.errors
}

// Describe 提供启动日志所需的后端形态，不暴露 DSN 或口令。
func (p *PostgresCache) Describe() string { return "postgres KV/TTL (samwaf_kv v1)" }

// Close 幂等取消清理、等待协程退出并关闭连接池，应在代理业务已排空后调用。
func (p *PostgresCache) Close() error {
	p.once.Do(func() { p.cancel(); <-p.done; _ = p.db.Close() })
	return nil
}
