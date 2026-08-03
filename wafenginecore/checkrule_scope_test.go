package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"testing"
)

// newTestEngineWithGlobalRule 造一个只挂了"全局网站"的引擎，全局规则用 globalRule 文本
// globalRule 传空串表示全局网站没有任何规则
func newTestEngineWithGlobalRule(t *testing.T, globalRule string) *WafEngine {
	t.Helper()
	waf := &WafEngine{}
	waf.InitRouting()
	if globalRule == "" {
		return waf
	}
	globalHost := &wafenginmodel.HostSafe{
		Host: model.Hosts{GUARD_STATUS: 1, GLOBAL_HOST: 1},
		Rule: buildRuleHelper(t, globalRule),
	}
	waf.withWriteTable(func(nt *routingTable) {
		nt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = globalHost
	})
	return waf
}

// newTestSiteHost 造一个挂了站点规则的 HostSafe，siteRule 传空串表示站点没有规则
func newTestSiteHost(t *testing.T, siteRule string) *wafenginmodel.HostSafe {
	t.Helper()
	h := &wafenginmodel.HostSafe{Host: model.Hosts{GUARD_STATUS: 1}}
	if siteRule != "" {
		h.Rule = buildRuleHelper(t, siteRule)
	}
	return h
}

// TestCheckRule_CrossScopeArbitration 站点规则与全局规则按 salience 统一仲裁
//
// 覆盖 issue #907：站点白名单 salience 90 必须能压过全局拦截 salience 10；
// 同时保证老配置（两侧都是默认 salience 10）行为不变——全局拦截依旧赢。
func TestCheckRule_CrossScopeArbitration(t *testing.T) {
	const testIP = "1.2.3.4"

	// 站点放行规则模板：命中测试 IP
	siteAllow := func(salience string, action string) string {
		return `
rule Rsite001 "站点白名单" salience ` + salience + ` {
    when MF.SRC_IP == "` + testIP + `"
    then ` + action + `
}`
	}
	// 全局拦截规则模板：命中测试 IP
	globalRule := func(salience string, action string) string {
		return `
rule Rglobal001 "全局屏蔽" salience ` + salience + ` {
    when MF.SRC_IP == "` + testIP + `"
    then ` + action + `
}`
	}

	cases := []struct {
		name        string
		siteRule    string
		globalRule  string
		wantBlock   bool
		wantAllow   bool
		wantLogOnly bool
		wantJump    bool
	}{
		{
			name:       "#907场景_站点放行salience90压过全局拦截salience10",
			siteRule:   siteAllow("90", "RF.Allow();"),
			globalRule: globalRule("10", "RF.Deny();"),
			wantAllow:  true,
		},
		{
			name:       "同优先级_全局拦截仍旧赢_兼容老配置",
			siteRule:   siteAllow("10", "RF.Allow();"),
			globalRule: globalRule("10", "RF.Deny();"),
			wantBlock:  true,
		},
		{
			name:       "全局放行salience90压过站点拦截salience10",
			siteRule:   siteAllow("10", "RF.Deny();"),
			globalRule: globalRule("90", "RF.Allow();"),
			wantAllow:  true,
		},
		{
			name:       "站点拦截salience90压过全局放行salience10",
			siteRule:   siteAllow("90", "RF.Deny();"),
			globalRule: globalRule("10", "RF.Allow();"),
			wantBlock:  true,
		},
		{
			name:       "站点AllowAll压过全局拦截_并跳过后续全部检测",
			siteRule:   siteAllow("90", "RF.AllowAll();"),
			globalRule: globalRule("10", "RF.Deny();"),
			wantAllow:  true,
			wantJump:   true,
		},
		{
			name:        "站点仅记录salience90压过全局拦截_不拦截",
			siteRule:    siteAllow("90", "RF.Log();"),
			globalRule:  globalRule("10", "RF.Deny();"),
			wantLogOnly: true,
		},
		{
			name:       "站点无规则_全局拦截生效",
			siteRule:   "",
			globalRule: globalRule("10", "RF.Deny();"),
			wantBlock:  true,
		},
		{
			name:      "全局无规则_站点放行生效",
			siteRule:  siteAllow("10", "RF.Allow();"),
			wantAllow: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			waf := newTestEngineWithGlobalRule(t, tc.globalRule)
			hostTarget := newTestSiteHost(t, tc.siteRule)
			weblog := &innerbean.WebLog{SRC_IP: testIP, URL: "/download"}

			result := waf.CheckRule(nil, weblog, nil, hostTarget, nil)

			if result.IsBlock != tc.wantBlock {
				t.Errorf("IsBlock 期望 %v 实际 %v (Title=%s)", tc.wantBlock, result.IsBlock, result.Title)
			}
			if result.IsRuleAllow != tc.wantAllow {
				t.Errorf("IsRuleAllow 期望 %v 实际 %v (Title=%s)", tc.wantAllow, result.IsRuleAllow, result.Title)
			}
			if result.IsLogOnly != tc.wantLogOnly {
				t.Errorf("IsLogOnly 期望 %v 实际 %v (Title=%s)", tc.wantLogOnly, result.IsLogOnly, result.Title)
			}
			if result.JumpGuardResult != tc.wantJump {
				t.Errorf("JumpGuardResult 期望 %v 实际 %v", tc.wantJump, result.JumpGuardResult)
			}
		})
	}
}

// TestCheckRule_NoMatch 两侧都不命中时不拦不放
func TestCheckRule_NoMatch(t *testing.T) {
	waf := newTestEngineWithGlobalRule(t, `
rule Rglobal001 "全局屏蔽" salience 10 {
    when MF.SRC_IP == "9.9.9.9"
    then RF.Deny();
}`)
	hostTarget := newTestSiteHost(t, `
rule Rsite001 "站点白名单" salience 90 {
    when MF.SRC_IP == "1.2.3.4"
    then RF.Allow();
}`)

	result := waf.CheckRule(nil, &innerbean.WebLog{SRC_IP: "8.8.8.8"}, nil, hostTarget, nil)
	if result.IsBlock || result.IsRuleAllow || result.IsLogOnly {
		t.Fatalf("两侧都不命中时应无任何动作, 实际 %+v", result)
	}
}

// TestCheckRule_AllowSkipModulesUnion 同优先级两侧都放行时，跳过模块取并集
func TestCheckRule_AllowSkipModulesUnion(t *testing.T) {
	const testIP = "1.2.3.4"
	waf := newTestEngineWithGlobalRule(t, `
rule Rglobal001 "全局放行" salience 50 {
    when MF.SRC_IP == "`+testIP+`"
    then RF.Allow("AI", "CC");
}`)
	hostTarget := newTestSiteHost(t, `
rule Rsite001 "站点放行" salience 50 {
    when MF.SRC_IP == "`+testIP+`"
    then RF.Allow("CC", "XSS");
}`)

	result := waf.CheckRule(nil, &innerbean.WebLog{SRC_IP: testIP}, nil, hostTarget, nil)
	if !result.IsRuleAllow {
		t.Fatalf("应放行, 实际 %+v", result)
	}
	got := map[string]bool{}
	for _, m := range result.SkipModules {
		got[m] = true
	}
	for _, want := range []string{"AI", "CC", "XSS"} {
		if !got[want] {
			t.Errorf("跳过模块应包含 %s, 实际 %v", want, result.SkipModules)
		}
	}
	if len(result.SkipModules) != 3 {
		t.Errorf("跳过模块应去重为3个, 实际 %v", result.SkipModules)
	}
}

// TestShouldRecordWebLog abnormal 模式下"命中了但没拦"的请求必须留痕
func TestShouldRecordWebLog(t *testing.T) {
	origin := global.GWAF_RUNTIME_RECORD_LOG_TYPE
	defer func() { global.GWAF_RUNTIME_RECORD_LOG_TYPE = origin }()

	cases := []struct {
		name       string
		logType    string
		weblog     *innerbean.WebLog
		excludeURL string
		want       bool
	}{
		{"all模式_普通放行也记", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/a"}, "", true},
		{"all模式_排除前缀命中不记", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/static/x.js"}, "/static", false},
		{"abnormal模式_普通放行不记", "abnormal",
			&innerbean.WebLog{ACTION: "放行", URL: "/a"}, "", false},
		{"abnormal模式_拦截要记", "abnormal",
			&innerbean.WebLog{ACTION: "阻止", URL: "/a"}, "", true},
		{"abnormal模式_自定义规则放行要留痕", "abnormal",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", RULE: "自定义规则放行:站点白名单"}, "", true},
		{"abnormal模式_自定义规则仅记录要留痕", "abnormal",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", RULE: "自定义规则记录:观察"}, "", true},
		{"abnormal模式_站点仅记录模式要留痕", "abnormal",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", LogOnlyMode: 1}, "", true},
		{"abnormal模式_命中规则但URL被排除仍不记", "abnormal",
			&innerbean.WebLog{ACTION: "放行", URL: "/static/x.js", RULE: "自定义规则放行:x"}, "/static", false},
		{"排除列表里的空行不该吞掉全部日志", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/a"}, "\n  \n", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global.GWAF_RUNTIME_RECORD_LOG_TYPE = tc.logType
			if got := shouldRecordWebLog(tc.weblog, tc.excludeURL); got != tc.want {
				t.Errorf("期望 %v 实际 %v", tc.want, got)
			}
		})
	}
}
