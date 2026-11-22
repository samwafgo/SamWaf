package wafenginecore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"SamWaf/cache"
	"SamWaf/global"
)

// countedBanStore 检查请求是否使用一次整组查询，并能注入真实的后端错误语义。
type countedBanStore struct {
	cache.CacheStore
	calls   int
	keys    []string
	failure error
}

// ExistsManyE 保留内存适配器数据，同时记录合并查询次数。
func (s *countedBanStore) ExistsManyE(ctx context.Context, keys []string) (map[string]bool, error) {
	s.calls++
	s.keys = append([]string(nil), keys...)
	if s.failure != nil {
		return nil, s.failure
	}
	return cache.ExistsKeysE(ctx, s.CacheStore, keys)
}

// TestIPBansUseOneLookupAndFailClosed 验证命中缓存/封禁前的数据库故障返回 503，不当作访客攻击。
func TestIPBansUseOneLookupAndFailClosed(t *testing.T) {
	waf, cleanup := setupCCBanEngine(t, "10.1.2.3", nil)
	defer cleanup()
	store := &countedBanStore{CacheStore: global.GCACHE_WAFCACHE}
	global.GCACHE_WAFCACHE = store
	state, err := lookupIPBans(context.Background(), "ccb-code", "10.1.2.3", "10.1.2.3", "nic")
	if err != nil || state.CCKey == "" || store.calls != 1 || len(store.keys) != 4 {
		t.Fatalf("state=%+v calls=%d keys=%d err=%v", state, store.calls, len(store.keys), err)
	}
	store.failure = cache.ErrCacheBackend
	writer := httptest.NewRecorder()
	doCCBanRequest(waf, writer, "/backend-failure")
	if writer.Code != http.StatusServiceUnavailable || writer.Header().Get("Retry-After") == "" {
		t.Fatalf("backend failure returned %d: %s", writer.Code, writer.Body.String())
	}
}
