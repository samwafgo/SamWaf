package wafwebcache

import (
	"net/http"
	"testing"
	"time"
)

// TestTierClient304CannotValidateUnrelatedStaleObject 防止客户端自带校验器把没有校验器的旧正文错误续期。
func TestTierClient304CannotValidateUnrelatedStaleObject(t *testing.T) {
	h, c := tierEnv(t)
	h.CacheRule[0].CacheTime = 1
	calls := 0
	origin := func(r *http.Request) *http.Response {
		calls++
		if r.Header.Get("If-None-Match") != "" {
			return tierResponse(r, 304, "", nil)
		}
		if calls == 1 {
			return tierResponse(r, 200, "old-without-validator", nil)
		}
		return tierResponse(r, 200, "new-without-validator", nil)
	}
	exchange(t, h, c, tierRequest("/"), origin)
	time.Sleep(1100 * time.Millisecond)
	r := tierRequest("/")
	r.Header.Set("If-None-Match", `"client-only"`)
	_, head, status := exchange(t, h, c, r, origin)
	if status != 304 || head.Get("X-Cache") == "REVALIDATED" {
		t.Fatal("unrelated client 304 was treated as validation of the old object")
	}
	body, _, _ := exchange(t, h, c, tierRequest("/"), origin)
	if body != "new-without-validator" || calls != 3 {
		t.Fatalf("stale object renewed without a validator: body=%q calls=%d", body, calls)
	}
}

// TestTierAgePreservesOriginApparentAge 验证 Date 推导的源站年龄不会在命中时被较小的 Age 重置。
func TestTierAgePreservesOriginApparentAge(t *testing.T) {
	h, c := tierEnv(t)
	origin := func(r *http.Request) *http.Response {
		return tierResponse(r, 200, "body", http.Header{"Cache-Control": {"max-age=60"}, "Age": {"2"}, "Date": {time.Now().Add(-30 * time.Second).UTC().Format(http.TimeFormat)}})
	}
	exchange(t, h, c, tierRequest("/"), origin)
	_, head, _ := exchange(t, h, c, tierRequest("/"), origin)
	if age := head.Get("Age"); age != "30" && age != "31" {
		t.Fatalf("origin apparent age was reset: %q", age)
	}
}
