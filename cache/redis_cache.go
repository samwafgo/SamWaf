package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache Redis缓存实现，满足CacheStore接口
type RedisCache struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisCache 创建Redis缓存实例，连接失败时返回 error
func NewRedisCache(cfg *RedisCacheConfig) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		MaxRetries:   3, // 断连后自动重试3次（go-redis 默认行为，此处显式声明）
		PoolSize:     10,
		MinIdleConns: 2,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("Redis连接失败 %s:%d : %w", cfg.Host, cfg.Port, err)
	}
	return &RedisCache{
		client: client,
		ctx:    context.Background(),
	}, nil
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
	r.client.Set(r.ctx, key, encoded, ttl)
}

// SetWithTTlRenewTime Redis不保留原始createTime，直接等同于SetWithTTl
func (r *RedisCache) SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration) {
	r.SetWithTTl(key, value, ttl)
}

func (r *RedisCache) Get(key string) interface{} {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return nil
	}
	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return val
	}
	return result
}

func (r *RedisCache) GetAs(key string, out interface{}) error {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return errors.New("数据不存在")
	}
	return json.Unmarshal([]byte(val), out)
}

func (r *RedisCache) GetBytes(key string) ([]byte, error) {
	val, err := r.client.Get(r.ctx, key).Bytes()
	if err != nil {
		return nil, errors.New("数据不存在")
	}
	var result []byte
	if err := json.Unmarshal(val, &result); err != nil {
		return val, nil
	}
	return result, nil
}

func (r *RedisCache) GetString(key string) (string, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return "", errors.New("数据不存在")
	}
	var result string
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return val, nil
	}
	return result, nil
}

func (r *RedisCache) GetInt(key string) (int, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		return -1, errors.New("数据不存在")
	}
	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return -1, errors.New("数据不存在")
	}
	switch v := result.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	}
	return -1, errors.New("数据不存在")
}

func (r *RedisCache) IsKeyExist(key string) bool {
	n, err := r.client.Exists(r.ctx, key).Result()
	return err == nil && n > 0
}

func (r *RedisCache) Remove(key string) interface{} {
	r.client.Del(r.ctx, key)
	return nil
}

func (r *RedisCache) GetExpireTime(key string) (time.Time, error) {
	ttl, err := r.client.TTL(r.ctx, key).Result()
	if err != nil || ttl < 0 {
		return time.Time{}, errors.New("数据不存在或已过期")
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
		keys, nextCursor, err := r.client.Scan(r.ctx, cursor, pattern, 100).Result()
		if err != nil {
			break
		}
		for _, key := range keys {
			if prefix != "" && !strings.HasPrefix(key, prefix) {
				continue
			}
			ttl, err := r.client.TTL(r.ctx, key).Result()
			if err == nil && ttl > 0 {
				result[key] = ttl
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return result
}
