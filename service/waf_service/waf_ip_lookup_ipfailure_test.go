package waf_service

import (
	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/wafipban"
	"strings"
	"testing"
)

// TestIPFailureEffectByRecord 查询展示的 effect/文案判定：
// 带阈值戳（规则真实命中过）才是 block，纯失败记分卡报 none——
// 与封禁列表的收录判据一致，避免"有失败记录"被误读成"已被拦截"。
func TestIPFailureEffectByRecord(t *testing.T) {
	oldLock := global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME
	global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = 10
	t.Cleanup(func() { global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = oldLock })

	cases := []struct {
		name       string
		record     *wafipban.IPFailureRecord
		remain     string
		wantEffect string
		wantDetail []string
	}{
		{
			name:       "无记录兜底",
			record:     nil,
			wantEffect: "none",
			wantDetail: []string{"有失败记录"},
		},
		{
			name: "仅有失败未触发规则",
			record: &wafipban.IPFailureRecord{
				Count: 3, TriggerMinutes: 0, TriggerCount: 0,
			},
			wantEffect: "none",
			wantDetail: []string{"失败3次", "未触发封禁规则"},
		},
		{
			name: "规则命中过带阈值戳",
			record: &wafipban.IPFailureRecord{
				Count: 12, TriggerMinutes: 5, TriggerCount: 10,
			},
			wantEffect: "block",
			wantDetail: []string{"5分钟内失败10次触发封禁"},
		},
		{
			name: "剩余时间拼在文案末尾",
			record: &wafipban.IPFailureRecord{
				Count: 12, TriggerMinutes: 5, TriggerCount: 10,
			},
			remain:     "9分钟",
			wantEffect: "block",
			wantDetail: []string{"触发封禁", "，剩余9分钟"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effect, detail := ipFailureEffect(tc.record, tc.remain)
			if effect != tc.wantEffect {
				t.Fatalf("effect 应为 %s，实际 %s（detail=%s）", tc.wantEffect, effect, detail)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(detail, want) {
					t.Fatalf("文案应包含 %q，实际 %q", want, detail)
				}
			}
		})
	}
}

// TestLookupIPFailureEffect 端到端：真实管理器 + 内存缓存，验证 Lookup 的 effect 判定
// 跟随"是否带阈值戳"切换。InitIPBanManager 是 sync.Once，本包测试只在此初始化一次。
func TestLookupIPFailureEffect(t *testing.T) {
	store := cache.InitWafCache()
	oldCache := global.GCACHE_WAFCACHE
	oldEnabled := global.GCONFIG_IP_FAILURE_BAN_ENABLED
	global.GCACHE_WAFCACHE = store
	global.GCONFIG_IP_FAILURE_BAN_ENABLED = 1
	t.Cleanup(func() {
		global.GCACHE_WAFCACHE = oldCache
		global.GCONFIG_IP_FAILURE_BAN_ENABLED = oldEnabled
	})
	wafipban.InitIPBanManager(store)

	ip := "192.0.2.20"
	manager := wafipban.GetIPFailureManager()

	lookup := func() (string, string) {
		t.Helper()
		resp, err := WafIPLookupServiceApp.Lookup(ip, []string{"ip_failure"})
		if err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		if len(resp.Hits) != 1 {
			t.Fatalf("应命中1条 IP失败封禁，实际 %d 条", len(resp.Hits))
		}
		return resp.Hits[0].Effect, resp.Hits[0].Detail
	}

	// 阶段1：只有失败记录，未达阈值 → none
	manager.RecordFailure(&innerbean.WebLog{SRC_IP: ip, STATUS_CODE: 403})
	effect, detail := lookup()
	if effect != "none" {
		t.Fatalf("未触发规则应为 none，实际 %s（detail=%s）", effect, detail)
	}
	if !strings.Contains(detail, "未触发封禁规则") {
		t.Fatalf("文案应说明未触发规则，实际 %q", detail)
	}

	// 阶段2：规则命中盖阈值戳 → block
	manager.RecordFailureThreshold(ip, 5, 10)
	effect, detail = lookup()
	if effect != "block" {
		t.Fatalf("带阈值戳应为 block，实际 %s（detail=%s）", effect, detail)
	}
	if !strings.Contains(detail, "5分钟内失败10次触发封禁") {
		t.Fatalf("文案应包含触发信息，实际 %q", detail)
	}

	// 阶段3：清除记录 → 不再命中
	manager.ClearIPFailure(ip)
	resp, err := WafIPLookupServiceApp.Lookup(ip, []string{"ip_failure"})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(resp.Hits) != 0 {
		t.Fatalf("清除后不应再命中，实际 %+v", resp.Hits)
	}
}
