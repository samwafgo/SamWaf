package middleware

import (
	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 鉴权读不到令牌时，"键不存在"与"缓存后端不可用"必须走不同的出口：
// 前者是登录态失效，后者只是这次没读到——把后者也判成失效，等于让一次
// 缓存抖动把正在使用管理端的人踢回登录页。下面两个用例把分流钉死。

// stubCache 只实现取值分支，其余方法满足接口即可
type stubCache struct {
	err   error          // GetAsEx 返回的错误
	value map[string]any // err 为 nil 时写入 out 的内容
}

func (s *stubCache) Set(string, interface{})                                {}
func (s *stubCache) SetWithTTl(string, interface{}, time.Duration)          {}
func (s *stubCache) SetWithTTlRenewTime(string, interface{}, time.Duration) {}
func (s *stubCache) Get(string) interface{}                                 { return nil }
func (s *stubCache) GetAs(key string, out interface{}) error {
	return s.GetAsEx(key, out, 0)
}
func (s *stubCache) GetAsEx(_ string, out interface{}, _ time.Duration) error {
	if s.err != nil {
		return s.err
	}
	b, _ := json.Marshal(s.value)
	return json.Unmarshal(b, out)
}
func (s *stubCache) Touch(string, time.Duration) error { return nil }
func (s *stubCache) GetBytes(string) ([]byte, error)   { return nil, cache.ErrCacheMiss }
func (s *stubCache) GetString(string) (string, error)  { return "", cache.ErrCacheMiss }
func (s *stubCache) GetInt(string) (int, error)        { return -1, cache.ErrCacheMiss }
func (s *stubCache) IsKeyExist(string) bool            { return false }
func (s *stubCache) ExistsE(string) (bool, error)      { return false, nil }
func (s *stubCache) Remove(string) interface{}         { return nil }
func (s *stubCache) GetExpireTime(string) (time.Time, error) {
	return time.Time{}, cache.ErrCacheMiss
}
func (s *stubCache) ListAvailableKeys() map[string]time.Duration { return nil }
func (s *stubCache) ListAvailableKeysWithPrefix(string) map[string]time.Duration {
	return nil
}

// runAuthWith 用指定缓存跑一次带令牌的请求，返回响应码与后续处理是否被执行
func runAuthWith(t *testing.T, store cache.CacheStore) (int, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	oldStore := global.GCACHE_WAFCACHE
	oldLegacy := global.GCONFIG_COMM_LEGACY_KEY
	global.GCACHE_WAFCACHE = store
	// 固定走 legacy 加密分支，避免握手状态影响响应码
	global.GCONFIG_COMM_LEGACY_KEY = true
	t.Cleanup(func() {
		global.GCACHE_WAFCACHE = oldStore
		global.GCONFIG_COMM_LEGACY_KEY = oldLegacy
	})

	reached := false
	r := gin.New()
	r.GET("/api/v1/ping", Auth(), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	req.Header.Set("X-Token", "0d42ce0c1f2a3b4c5d6e7f8091a2b3c4")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法 JSON：%v body=%s", err, w.Body.String())
	}
	return body.Code, reached
}

func TestAuthCacheBackendErrorDoesNotForceRelogin(t *testing.T) {
	code, reached := runAuthWith(t, &stubCache{err: cache.ErrCacheBackend})

	if code == response.AUTHFAIL {
		t.Fatal("缓存后端不可用被判成了登录态失效，前端会据此清登录态跳登录页")
	}
	if code != response.BACKEND_UNAVAILABLE {
		t.Fatalf("期望响应码 %v，实际 %v", response.BACKEND_UNAVAILABLE, code)
	}
	if reached {
		t.Fatal("后端不可用时不得放行到业务处理")
	}
}

func TestAuthCacheMissStillRequiresRelogin(t *testing.T) {
	code, reached := runAuthWith(t, &stubCache{err: cache.ErrCacheMiss})

	if code != response.AUTHFAIL {
		t.Fatalf("令牌确实不存在时应返回 %v，实际 %v", response.AUTHFAIL, code)
	}
	if reached {
		t.Fatal("令牌无效时不得放行到业务处理")
	}
}

// 包装过的后端错误（带原始 Redis 错误信息）同样要认得出来
func TestAuthWrappedBackendErrorDoesNotForceRelogin(t *testing.T) {
	wrapped := &stubCache{err: fmt.Errorf("%w: %v", cache.ErrCacheBackend, "dial tcp 127.0.0.1:6379: i/o timeout")}
	code, _ := runAuthWith(t, wrapped)

	if code != response.BACKEND_UNAVAILABLE {
		t.Fatalf("包装后的后端错误期望 %v，实际 %v", response.BACKEND_UNAVAILABLE, code)
	}
}
