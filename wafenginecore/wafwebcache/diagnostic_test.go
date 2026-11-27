package wafwebcache

import (
	"net/http"
	"testing"
)

// TestTierDiagnosticsCannotBeSpoofedByOrigin 校验 MISS/BYPASS 都只输出可信诊断，源站大小写变体保留头不能穿透。
func TestTierDiagnosticsCannotBeSpoofedByOrigin(t *testing.T) {
	h, c := tierEnv(t)
	origin := func(r *http.Request) *http.Response {
		return tierResponse(r, 200, "body", http.Header{"x-cache": {"forged"}, "X-Cache-Layer": {"forged"}, "x-tier-token": {"synthetic-internal"}})
	}
	_, head, _ := exchange(t, h, c, tierRequest("/"), origin)
	if head.Get("X-Cache") != "MISS" || head.Get("X-Cache-Layer") != "origin" || present(head, "X-Tier-Token") || len(values(head, "X-Cache")) != 1 {
		t.Fatalf("untrusted diagnostics survived: %v", head)
	}
	r := tierRequest("/")
	r.Header.Set("Cookie", "synthetic=value")
	_, head, _ = exchange(t, h, c, r, origin)
	if head.Get("X-Cache") != "BYPASS" || head.Get("X-Cache-Layer") != "off" || present(head, "X-Tier-Token") {
		t.Fatalf("bypass diagnostics spoofed: %v", head)
	}
}
