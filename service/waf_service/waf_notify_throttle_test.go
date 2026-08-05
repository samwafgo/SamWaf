package waf_service

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// newTestSub 造一个订阅：mode + 频控细项
func newTestSub(id, messageType, mode string, cfg model.NotifyThrottleConfig) model.NotifySubscription {
	buf, _ := json.Marshal(cfg)
	sub := model.NotifySubscription{
		ChannelId:    "ch-" + id,
		MessageType:  messageType,
		Status:       1,
		ThrottleMode: mode,
		ThrottleJSON: string(buf),
	}
	sub.Id = id
	return sub
}

// ruleEvent 造一条规则触发事件
func ruleEvent(domain, ruleInfo, ip string) NotifyEvent {
	return WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.RuleMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: "srv"},
		Domain:          domain,
		RuleInfo:        ruleInfo,
		Ip:              ip,
	})
}

// TestCooldownNotBypassedByPayloadVariation 锁死 issue #822 的根因。
//
// 老实现用「规则原文」当频控 key，攻击方每换一次 payload 就产生一个新 key，
// 每个新 key 都算"首次出现→立即发送"，于是冷却完全失效、飞书被刷屏。
// 现在 key 由「域名 + 攻击类型」这类稳定维度构成，1000 条变体只应放行第一条。
func TestCooldownNotBypassedByPayloadVariation(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	sub := newTestSub("sub-cooldown", model.MSG_TYPE_RULE_TRIGGER, model.ThrottleModeCooldown,
		model.NotifyThrottleConfig{CooldownStepsSec: []int{60, 300, 900}})

	sent := 0
	for i := 0; i < 1000; i++ {
		// 每次规则原文都不同，模拟攻击方不断变换 payload
		ev := ruleEvent("www.example.com", "SQL注入检测 payload="+strings.Repeat("a", i%17)+string(rune('A'+i%26)), "1.2.3.4")
		d := WafNotifyThrottleServiceApp.Decide(sub, ev)
		if d.Action == ThrottleActionSend {
			sent++
			WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)
		}
	}
	if sent != 1 {
		t.Fatalf("变换 payload 的 1000 条事件应只发出 1 条（冷却期内），实际发出 %d 条", sent)
	}
}

// TestCooldownLadderAndSuppressCount 冷却梯度生效，且抑制条数能被正确带出来
func TestCooldownLadderAndSuppressCount(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	// 用 1 秒的极短梯度，避免单测睡太久
	sub := newTestSub("sub-ladder", model.MSG_TYPE_RULE_TRIGGER, model.ThrottleModeCooldown,
		model.NotifyThrottleConfig{CooldownStepsSec: []int{1, 1}, CooldownResetSec: 3600})

	ev := ruleEvent("a.com", "规则A", "1.1.1.1")

	d := WafNotifyThrottleServiceApp.Decide(sub, ev)
	if d.Action != ThrottleActionSend {
		t.Fatalf("首条应立即发送，实际 %s", d.Action)
	}
	WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)

	for i := 0; i < 5; i++ {
		if got := WafNotifyThrottleServiceApp.Decide(sub, ev); got.Action != ThrottleActionSuppress ||
			got.Reason != model.SuppressReasonCooldown {
			t.Fatalf("冷却期内应被抑制，实际 action=%s reason=%s", got.Action, got.Reason)
		}
	}

	time.Sleep(1100 * time.Millisecond)
	d2 := WafNotifyThrottleServiceApp.Decide(sub, ev)
	if d2.Action != ThrottleActionSend {
		t.Fatalf("冷却结束后应放行，实际 %s", d2.Action)
	}
	if d2.SuppressedNum != 5 {
		t.Fatalf("应带出冷却期内被压掉的 5 条，实际 %d", d2.SuppressedNum)
	}
	_, count := WafNotifyThrottleServiceApp.NoteSent(d2.DedupKey)
	if count != 5 {
		t.Fatalf("NoteSent 应返回抑制条数 5，实际 %d", count)
	}
	// 结算之后计数要归零，否则下一条会重复报数
	if d3 := WafNotifyThrottleServiceApp.Decide(sub, ev); d3.SuppressedNum != 0 {
		t.Fatalf("结算后抑制计数应归零，实际 %d", d3.SuppressedNum)
	}
}

// TestChannelsAreIndependent 同一事件在两个订阅上各管各的，
// 这正是老实现做不到的"飞书只收严重告警、邮件收全量"
func TestChannelsAreIndependent(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	cold := newTestSub("sub-a", model.MSG_TYPE_RULE_TRIGGER, model.ThrottleModeCooldown,
		model.NotifyThrottleConfig{CooldownStepsSec: []int{600}})
	realtime := newTestSub("sub-b", model.MSG_TYPE_RULE_TRIGGER, model.ThrottleModeRealtime,
		model.NotifyThrottleConfig{})

	ev := ruleEvent("a.com", "规则A", "1.1.1.1")

	coldSent, realtimeSent := 0, 0
	for i := 0; i < 10; i++ {
		if d := WafNotifyThrottleServiceApp.Decide(cold, ev); d.Action == ThrottleActionSend {
			coldSent++
			WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)
		}
		if d := WafNotifyThrottleServiceApp.Decide(realtime, ev); d.Action == ThrottleActionSend {
			realtimeSent++
			WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)
		}
	}
	if coldSent != 1 {
		t.Fatalf("冷却订阅应只发 1 条，实际 %d", coldSent)
	}
	if realtimeSent != 10 {
		t.Fatalf("直发订阅应发满 10 条，实际 %d", realtimeSent)
	}
}

// TestMaxPerHour 每小时上限是硬保护
func TestMaxPerHour(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	sub := newTestSub("sub-limit", model.MSG_TYPE_RULE_TRIGGER, model.ThrottleModeRealtime,
		model.NotifyThrottleConfig{MaxPerHour: 3})
	ev := ruleEvent("a.com", "规则A", "1.1.1.1")

	sent, limited := 0, 0
	for i := 0; i < 20; i++ {
		d := WafNotifyThrottleServiceApp.Decide(sub, ev)
		switch {
		case d.Action == ThrottleActionSend:
			sent++
			WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)
		case d.Reason == model.SuppressReasonRateLimit:
			limited++
		}
	}
	if sent != 3 {
		t.Fatalf("每小时上限 3，应只发 3 条，实际 %d", sent)
	}
	if limited != 17 {
		t.Fatalf("其余 17 条应记为超限抑制，实际 %d", limited)
	}
}

// TestSuppressLogNotFlooding 抑制日志不能自己把库刷爆：一万次抑制只能触发个位数次写库
func TestSuppressLogNotFlooding(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	key := "sub-x:deadbeef"

	writes := 0
	for i := 0; i < 10000; i++ {
		action := WafNotifyThrottleServiceApp.OnSuppress(key)
		if action.WriteNew {
			writes++
			WafNotifyThrottleServiceApp.SetSuppressLogID(key, "log-id")
		}
	}
	if writes != 1 {
		t.Fatalf("10000 次抑制在同一滚动窗口内只应写 1 条日志，实际 %d", writes)
	}
}

// TestQuietHoursCrossMidnight 免打扰跨天区间
func TestQuietHoursCrossMidnight(t *testing.T) {
	day := func(h, m int) time.Time { return time.Date(2026, 8, 5, h, m, 0, 0, time.Local) }
	cases := []struct {
		quiet string
		at    time.Time
		want  bool
	}{
		{"23:00-07:00", day(23, 30), true},
		{"23:00-07:00", day(2, 0), true},
		{"23:00-07:00", day(6, 59), true},
		{"23:00-07:00", day(7, 0), false},
		{"23:00-07:00", day(12, 0), false},
		{"09:00-18:00", day(12, 0), true},
		{"09:00-18:00", day(8, 59), false},
		{"", day(3, 0), false},
		{"invalid", day(3, 0), false},
	}
	for _, c := range cases {
		if got := isInQuietHours(c.quiet, c.at); got != c.want {
			t.Errorf("isInQuietHours(%q, %s)=%v, want %v", c.quiet, c.at.Format("15:04"), got, c.want)
		}
	}
}

// TestNotifyFilter 过滤条件；空配置必须放行（宁可多发也不能吞掉告警）
func TestNotifyFilter(t *testing.T) {
	ev := ruleEvent("api.example.com", "SQL注入检测", "10.0.0.5")

	if !MatchNotifyFilter(model.NotifyFilterConfig{}, ev) {
		t.Fatal("空过滤条件必须放行")
	}
	if !MatchNotifyFilter(model.NotifyFilterConfig{Domains: []string{"*.example.com"}}, ev) {
		t.Fatal("通配域名应命中")
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{Domains: []string{"other.com"}}, ev) {
		t.Fatal("域名不匹配应被过滤")
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"10.0.0.0/8"}}, ev) {
		t.Fatal("命中排除网段应被过滤")
	}
	if !MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"192.168.0.0/16"}}, ev) {
		t.Fatal("未命中排除网段应放行")
	}
	if !MatchNotifyFilter(model.NotifyFilterConfig{Keywords: []string{"sql注入"}}, ev) {
		t.Fatal("关键字应忽略大小写命中")
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{Keywords: []string{"webshell"}}, ev) {
		t.Fatal("关键字未命中应被过滤")
	}
	// rule_trigger 是 warn 级，要求 critical 时应被过滤
	if MatchNotifyFilter(model.NotifyFilterConfig{MinSeverity: model.SeverityCritical}, ev) {
		t.Fatal("低于最低严重级别应被过滤")
	}
	if !MatchNotifyFilter(model.NotifyFilterConfig{MinSeverity: model.SeverityInfo}, ev) {
		t.Fatal("高于最低严重级别应放行")
	}
}

// TestThrottleConfigSanitize 非法配置一律归零（=继承默认），不能让脏数据进引擎
func TestThrottleConfigSanitize(t *testing.T) {
	cfg := model.NotifyThrottleConfig{
		AggregateWindowSec: 999999,
		AggregateMaxDetail: -3,
		CooldownStepsSec:   []int{0, 60, 999999, 120, 180, 240, 300},
		MaxPerHour:         -1,
		DedupKeys:          []string{"domain", "not_exist", "domain"},
		QuietHours:         "25:00-07:00",
	}.Sanitize()

	if cfg.AggregateWindowSec != 0 || cfg.AggregateMaxDetail != 0 || cfg.MaxPerHour != 0 {
		t.Fatalf("越界数值应归零，实际 %+v", cfg)
	}
	// 0 与 999999 越界被剔除，剩下 60/120/180/240/300 正好卡在 5 级上限
	if len(cfg.CooldownStepsSec) != 5 || cfg.CooldownStepsSec[0] != 60 || cfg.CooldownStepsSec[4] != 300 {
		t.Fatalf("非法梯度应被剔除且最多保留 5 级，实际 %v", cfg.CooldownStepsSec)
	}
	if len(cfg.DedupKeys) != 1 || cfg.DedupKeys[0] != model.DedupKeyDomain {
		t.Fatalf("非法/重复去重维度应被剔除，实际 %v", cfg.DedupKeys)
	}
	if cfg.QuietHours != "" {
		t.Fatalf("非法免打扰时段应清空，实际 %q", cfg.QuietHours)
	}
}

// TestResolveInheritsBuiltinDefaults 不配置任何东西时，生效参数必须等于升级前的硬编码行为
func TestResolveInheritsBuiltinDefaults(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	sub := model.NotifySubscription{MessageType: model.MSG_TYPE_RULE_TRIGGER, Status: 1}
	eff := WafNotifyThrottleServiceApp.Resolve(sub)

	if eff.Mode != model.ThrottleModeAggregate {
		t.Fatalf("默认模式应为聚合（与升级前一致），实际 %s", eff.Mode)
	}
	if eff.AggregateWindowSec != 10 || eff.AggregateMaxDetail != 10 {
		t.Fatalf("默认聚合窗口/条数应为 10/10，实际 %d/%d", eff.AggregateWindowSec, eff.AggregateMaxDetail)
	}
	if len(eff.CooldownStepsSec) != 3 || eff.CooldownStepsSec[0] != 60 || eff.CooldownStepsSec[2] != 900 {
		t.Fatalf("默认冷却梯度应为 60/300/900，实际 %v", eff.CooldownStepsSec)
	}
	if eff.MaxPerHour != 0 {
		t.Fatalf("默认不限每小时条数，实际 %d", eff.MaxPerHour)
	}
}

// TestBuildDedupKeySkipsEmptyDimension 缺维度的事件不能被混成同一个 key
func TestBuildDedupKeySkipsEmptyDimension(t *testing.T) {
	keys := []string{model.DedupKeyMessageType, model.DedupKeyDomain}
	a := buildDedupKey("s1", keys, ruleEvent("a.com", "r", "1.1.1.1"))
	b := buildDedupKey("s1", keys, ruleEvent("b.com", "r", "1.1.1.1"))
	c := buildDedupKey("s2", keys, ruleEvent("a.com", "r", "1.1.1.1"))
	if a == b {
		t.Fatal("不同域名应产生不同的去重 key")
	}
	if a == c {
		t.Fatal("不同订阅应产生不同的去重 key")
	}
}

// TestExtractHostFromUrl 攻击 URL 常常是畸形串，取不出域名要能安全返回空
func TestExtractHostFromUrl(t *testing.T) {
	cases := map[string]string{
		"https://www.a.com/x?y=1": "www.a.com",
		"http://1.2.3.4:8080/a":   "1.2.3.4",
		"www.b.com/x":             "www.b.com",
		"":                        "",
		"://///":                  "",
	}
	for in, want := range cases {
		if got := extractHostFromUrl(in); got != want {
			t.Errorf("extractHostFromUrl(%q)=%q, want %q", in, got, want)
		}
	}
	if got := extractHostFromUrl("http://" + strings.Repeat("a", 300) + "/x"); got != "" {
		t.Errorf("超长域名应返回空，实际长度 %d", len(got))
	}
}
