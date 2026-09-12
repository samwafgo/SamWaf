package cache

import (
	"SamWaf/common/zlog"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// defaultRedisOpTimeout 单次操作总上限。必须大于 ReadTimeout，
	// 否则正常的一次重试就会被掐断。
	defaultRedisOpTimeout = 5 * time.Second
	// backendErrLogInterval 后端故障时每请求都会报错，按间隔收敛日志
	backendErrLogInterval = 10 * time.Second
)

// RedisCache Redis缓存实现，满足CacheStore接口
type RedisCache struct {
	client    *redis.Client
	ctx       context.Context
	opTimeout time.Duration

	errMu    sync.Mutex
	errCount uint64
	errAt    time.Time
	errLast  string
	errLogAt time.Time
}

// NewRedisCache 创建Redis缓存实例，连接失败时返回 error
func NewRedisCache(cfg *RedisCacheConfig) (*RedisCache, error) {
	opt := &redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		MaxRetries:   3, // 断连后自动重试3次（go-redis 默认行为，此处显式声明）
		MinIdleConns: 2,
	}
	// 连接池留空时用 go-redis 默认值(10 × GOMAXPROCS)：管理端鉴权与业务检测共用同一个池，
	// 固定小值在多核机器上会先于 Redis 本身成为瓶颈。
	if cfg.PoolSize > 0 {
		opt.PoolSize = cfg.PoolSize
	}
	if cfg.PoolTimeout > 0 {
		opt.PoolTimeout = cfg.PoolTimeout
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("Redis连接失败 %s:%d : %w", cfg.Host, cfg.Port, err)
	}
	opTimeout := cfg.OpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultRedisOpTimeout
	}
	return &RedisCache{
		client:    client,
		ctx:       context.Background(),
		opTimeout: opTimeout,
	}, nil
}

// opCtx 每次操作独立超时，避免单次调用卡满 ReadTimeout × 重试次数
func (r *RedisCache) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.ctx, r.opTimeout)
}

// mapErr 把 go-redis 的错误分成"键不存在"与"后端不可用"两类
func (r *RedisCache) mapErr(err error) error {
	if errors.Is(err, redis.Nil) {
		return ErrCacheMiss
	}
	return fmt.Errorf("%w: %v", ErrCacheBackend, err)
}

// noteErr 记录后端错误并按间隔打日志。键名脱敏后才允许进日志。
func (r *RedisCache) noteErr(op, key string, err error) {
	if err == nil || errors.Is(err, redis.Nil) {
		return
	}
	now := time.Now()
	r.errMu.Lock()
	r.errCount++
	r.errAt = now
	r.errLast = err.Error()
	count := r.errCount
	shouldLog := now.Sub(r.errLogAt) >= backendErrLogInterval
	if shouldLog {
		r.errLogAt = now
	}
	r.errMu.Unlock()
	if shouldLog {
		zlog.Error(fmt.Sprintf("[缓存] Redis %v 失败 key:%v err:%v 累计失败:%v 次",
			op, maskCacheKey(key), err, count))
	}
}

// BackendStats 供运行诊断读取
func (r *RedisCache) BackendStats() BackendStats {
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return BackendStats{
		Backend:   "redis",
		ErrCount:  r.errCount,
		LastErrAt: r.errAt,
		LastErr:   r.errLast,
	}
}

// Describe 启动日志用，不含口令
func (r *RedisCache) Describe() string {
	opt := r.client.Options()
	return fmt.Sprintf("redis %v db=%v pool=%v", opt.Addr, opt.DB, opt.PoolSize)
}

func (r *RedisCache) encode(value interface{}) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *RedisCache) Set(key string, value interface{}) {
	r.SetWithTTl(key, value, 100*365*24*time.Hour)
}

func (r *RedisCache) SetWithTTl(key string, value interface{}, ttl time.Duration) {
	encoded, err := r.encode(value)
	if err != nil {
		return
	}
	ctx, cancel := r.opCtx()
	defer cancel()
	if err := r.client.Set(ctx, key, encoded, ttl).Err(); err != nil {
		r.noteErr("SET", key, err)
	}
}

// SetWithTTlRenewTime Redis不保留原始createTime，直接等同于SetWithTTl
func (r *RedisCache) SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration) {
	r.SetWithTTl(key, value, ttl)
}

func (r *RedisCache) Get(key string) interface{} {
	ctx, cancel := r.opCtx()
	defer cancel()
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		r.noteErr("GET", key, err)
		return nil
	}
	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return val
	}
	return result
}

func (r *RedisCache) GetAs(key string, out interface{}) error {
	ctx, cancel := r.opCtx()
	defer cancel()
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		r.noteErr("GET", key, err)
		return r.mapErr(err)
	}
	return json.Unmarshal([]byte(val), out)
}

// GetAsEx 一次往返完成读取与续期：Pipeline 里 GET + EXPIRE。
// 不用 GETEX 是因为它要求 Redis 6.2+，而 EXPIRE 对不存在的键返回 0、无副作用。
func (r *RedisCache) GetAsEx(key string, out interface{}, ttl time.Duration) error {
	if ttl <= 0 {
		return r.GetAs(key, out)
	}
	ctx, cancel := r.opCtx()
	defer cancel()
	pipe := r.client.Pipeline()
	getCmd := pipe.Get(ctx, key)
	expCmd := pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		r.noteErr("GET+EXPIRE", key, err)
	}
	// 以 GET 自己的结果为准：续期失败只是这次没续上，不该让本来读到的值作废
	val, err := getCmd.Result()
	if err != nil {
		r.noteErr("GET", key, err)
		return r.mapErr(err)
	}
	if eerr := expCmd.Err(); eerr != nil && !errors.Is(eerr, redis.Nil) {
		r.noteErr("EXPIRE", key, eerr)
	}
	return json.Unmarshal([]byte(val), out)
}

func (r *RedisCache) Touch(key string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	ctx, cancel := r.opCtx()
	defer cancel()
	ok, err := r.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		r.noteErr("EXPIRE", key, err)
		return r.mapErr(err)
	}
	if !ok {
		return ErrCacheMiss
	}
	return nil
}

func (r *RedisCache) GetBytes(key string) ([]byte, error) {
	ctx, cancel := r.opCtx()
	defer cancel()
	val, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		r.noteErr("GET", key, err)
		return nil, r.mapErr(err)
	}
	var result []byte
	if err := json.Unmarshal(val, &result); err != nil {
		return val, nil
	}
	return result, nil
}

func (r *RedisCache) GetString(key string) (string, error) {
	ctx, cancel := r.opCtx()
	defer cancel()
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		r.noteErr("GET", key, err)
		return "", r.mapErr(err)
	}
	var result string
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return val, nil
	}
	return result, nil
}

func (r *RedisCache) GetInt(key string) (int, error) {
	ctx, cancel := r.opCtx()
	defer cancel()
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		r.noteErr("GET", key, err)
		return -1, r.mapErr(err)
	}
	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return -1, ErrCacheMiss
	}
	switch v := result.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	}
	return -1, ErrCacheMiss
}

func (r *RedisCache) IsKeyExist(key string) bool {
	exist, _ := r.ExistsE(key)
	return exist
}

func (r *RedisCache) ExistsE(key string) (bool, error) {
	ctx, cancel := r.opCtx()
	defer cancel()
	n, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		r.noteErr("EXISTS", key, err)
		return false, r.mapErr(err)
	}
	return n > 0, nil
}

func (r *RedisCache) Remove(key string) interface{} {
	ctx, cancel := r.opCtx()
	defer cancel()
	if err := r.client.Del(ctx, key).Err(); err != nil {
		r.noteErr("DEL", key, err)
	}
	return nil
}

func (r *RedisCache) GetExpireTime(key string) (time.Time, error) {
	ctx, cancel := r.opCtx()
	defer cancel()
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		r.noteErr("TTL", key, err)
		return time.Time{}, r.mapErr(err)
	}
	if ttl < 0 {
		return time.Time{}, ErrCacheMiss
	}
	return time.Now().Add(ttl), nil
}

func (r *RedisCache) ListAvailableKeys() map[string]time.Duration {
	return r.ListAvailableKeysWithPrefix("")
}

func (r *RedisCache) ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration {
	pattern := "*"
	if prefix != "" {
		pattern = prefix + "*"
	}
	result := make(map[string]time.Duration)
	var cursor uint64
	for {
		ctx, cancel := r.opCtx()
		keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			cancel()
			r.noteErr("SCAN", prefix, err)
			break
		}
		for _, key := range keys {
			if prefix != "" && !strings.HasPrefix(key, prefix) {
				continue
			}
			ttl, err := r.client.TTL(ctx, key).Result()
			if err == nil && ttl > 0 {
				result[key] = ttl
			}
		}
		cancel()
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}
