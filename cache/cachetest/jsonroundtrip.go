// Package cachetest 提供模拟 JSON 类缓存后端(如 RedisCache)存取语义的测试替身：
// 写入时 JSON 编码，读取时 Get 解码到 interface{}（对象回来是 map[string]interface{}
// 泛型，不是原始结构体），GetAs 才解码到指定类型。
//
// 仅测试使用。不 import cache 包：方法签名与 CacheStore 结构性兼容，
// 由各测试在需要 CacheStore 的地方显式声明。
package cachetest

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// ErrMiss 键不存在或已过期
var ErrMiss = errors.New("cachetest: key miss")

type item struct {
	value     string
	expiresAt time.Time
}

// JSONRoundTrip 模拟 RedisCache 的值语义（不含网络与后端错误）
type JSONRoundTrip struct {
	mu   sync.Mutex
	data map[string]item
}

func NewJSONRoundTrip() *JSONRoundTrip {
	return &JSONRoundTrip{data: make(map[string]item)}
}

func (s *JSONRoundTrip) getRaw(key string) (item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.data[key]
	if !ok || time.Now().After(it.expiresAt) {
		return item{}, false
	}
	return it, true
}

func (s *JSONRoundTrip) Set(key string, value interface{}) {
	s.SetWithTTl(key, value, 100*365*24*time.Hour)
}

func (s *JSONRoundTrip) SetWithTTl(key string, value interface{}, ttl time.Duration) {
	b, err := json.Marshal(value)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = item{value: string(b), expiresAt: time.Now().Add(ttl)}
}

func (s *JSONRoundTrip) SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration) {
	s.SetWithTTl(key, value, ttl)
}

// Get 与 RedisCache.Get 同语义：JSON 解码到 interface{}，对象回来是 map 泛型
func (s *JSONRoundTrip) Get(key string) interface{} {
	it, ok := s.getRaw(key)
	if !ok {
		return nil
	}
	var result interface{}
	if err := json.Unmarshal([]byte(it.value), &result); err != nil {
		return it.value
	}
	return result
}

// GetAs 与 RedisCache.GetAs 同语义：JSON 解码到调用方指定的类型
func (s *JSONRoundTrip) GetAs(key string, out interface{}) error {
	it, ok := s.getRaw(key)
	if !ok {
		return ErrMiss
	}
	return json.Unmarshal([]byte(it.value), out)
}

func (s *JSONRoundTrip) GetAsEx(key string, out interface{}, ttl time.Duration) error {
	if err := s.GetAs(key, out); err != nil {
		return err
	}
	if ttl > 0 {
		s.mu.Lock()
		if it, ok := s.data[key]; ok {
			it.expiresAt = time.Now().Add(ttl)
			s.data[key] = it
		}
		s.mu.Unlock()
	}
	return nil
}

func (s *JSONRoundTrip) Touch(key string, ttl time.Duration) error {
	it, ok := s.getRaw(key)
	if !ok {
		return ErrMiss
	}
	if ttl > 0 {
		s.mu.Lock()
		it.expiresAt = time.Now().Add(ttl)
		s.data[key] = it
		s.mu.Unlock()
	}
	return nil
}

func (s *JSONRoundTrip) GetBytes(key string) ([]byte, error) {
	it, ok := s.getRaw(key)
	if !ok {
		return nil, ErrMiss
	}
	var result []byte
	if err := json.Unmarshal([]byte(it.value), &result); err != nil {
		return []byte(it.value), nil
	}
	return result, nil
}

func (s *JSONRoundTrip) GetString(key string) (string, error) {
	it, ok := s.getRaw(key)
	if !ok {
		return "", ErrMiss
	}
	var result string
	if err := json.Unmarshal([]byte(it.value), &result); err != nil {
		return it.value, nil
	}
	return result, nil
}

func (s *JSONRoundTrip) GetInt(key string) (int, error) {
	it, ok := s.getRaw(key)
	if !ok {
		return -1, ErrMiss
	}
	var result interface{}
	if err := json.Unmarshal([]byte(it.value), &result); err != nil {
		return -1, ErrMiss
	}
	switch v := result.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	}
	return -1, ErrMiss
}

func (s *JSONRoundTrip) IsKeyExist(key string) bool {
	exist, _ := s.ExistsE(key)
	return exist
}

func (s *JSONRoundTrip) ExistsE(key string) (bool, error) {
	_, ok := s.getRaw(key)
	return ok, nil
}

func (s *JSONRoundTrip) Remove(key string) interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *JSONRoundTrip) GetExpireTime(key string) (time.Time, error) {
	it, ok := s.getRaw(key)
	if !ok {
		return time.Time{}, ErrMiss
	}
	return it.expiresAt, nil
}

func (s *JSONRoundTrip) ListAvailableKeys() map[string]time.Duration {
	return s.ListAvailableKeysWithPrefix("")
}

func (s *JSONRoundTrip) ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration {
	result := make(map[string]time.Duration)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, it := range s.data {
		if now.After(it.expiresAt) {
			continue
		}
		if prefix != "" && !stringsHasPrefix(key, prefix) {
			continue
		}
		result[key] = it.expiresAt.Sub(now)
	}
	return result
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
