package ccrule

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, rule *model.AntiCCRule) *CompiledRule {
	t.Helper()
	cr, err := Compile(rule)
	if err != nil {
		t.Fatalf("编译规则失败: %v", err)
	}
	return cr
}

func ruleWithConds(t *testing.T, conds ...model.MatchCondition) *model.AntiCCRule {
	t.Helper()
	b, err := json.Marshal(conds)
	if err != nil {
		t.Fatalf("序列化条件失败: %v", err)
	}
	return &model.AntiCCRule{MatchMode: model.CCMatchModeSimple, MatchJson: string(b)}
}

func req(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func TestMatches_AllModeAlwaysHits(t *testing.T) {
	cr := mustCompile(t, &model.AntiCCRule{MatchMode: model.CCMatchModeAll})
	if !cr.Matches(req("GET", "/anything"), nil) {
		t.Error("all 模式应匹配任何请求")
	}
}

func TestMatches_ConditionsAreAnded(t *testing.T) {
	rule := ruleWithConds(t,
		model.MatchCondition{Field: model.CCFieldURI, Op: model.CCOpPrefix, Value: model.CCCondVal{"/api/login"}},
		model.MatchCondition{Field: model.CCFieldMethod, Op: model.CCOpEq, Value: model.CCCondVal{"POST"}},
	)
	cr := mustCompile(t, rule)

	if !cr.Matches(req("POST", "/api/login/submit"), nil) {
		t.Error("两个条件都满足时应命中")
	}
	if cr.Matches(req("GET", "/api/login/submit"), nil) {
		t.Error("方法不满足时不应命中（条件之间是 AND）")
	}
	if cr.Matches(req("POST", "/api/other"), nil) {
		t.Error("路径不满足时不应命中")
	}
}

// 排除静态资源用「扩展名 not_in」表达，这是纯请求侧、零延迟的做法。
func TestMatches_NotInExtensions(t *testing.T) {
	rule := ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldExt, Op: model.CCOpNotIn,
		Value: model.CCCondVal{".js", ".css", ".png"},
	})
	cr := mustCompile(t, rule)

	if !cr.Matches(req("GET", "/api/data"), nil) {
		t.Error("无扩展名的动态请求应命中")
	}
	if cr.Matches(req("GET", "/static/app.js"), nil) {
		t.Error(".js 在排除列表里，不应命中")
	}
	if cr.Matches(req("GET", "/img/logo.PNG"), nil) {
		t.Error("扩展名比较应忽略大小写")
	}
}

// 同名请求头可能出现多次，匹配语义是「任一取值命中即命中」。
func TestMatches_HeaderMultiValue(t *testing.T) {
	rule := ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldHeader, Key: "X-Tag", Op: model.CCOpEq, Value: model.CCCondVal{"beta"},
	})
	cr := mustCompile(t, rule)

	r := req("GET", "/")
	r.Header.Add("X-Tag", "alpha")
	r.Header.Add("X-Tag", "beta")
	if !cr.Matches(r, nil) {
		t.Error("同名头的任一取值命中即应命中")
	}
}

// 否定类条件的语义是「所有取值都不满足」，且字段缺失时视为成立。
func TestMatches_NegationAndMissingField(t *testing.T) {
	rule := ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldHeader, Key: "X-Tag", Op: model.CCOpNe, Value: model.CCCondVal{"beta"},
	})
	cr := mustCompile(t, rule)

	r := req("GET", "/")
	r.Header.Add("X-Tag", "alpha")
	r.Header.Add("X-Tag", "beta")
	if cr.Matches(r, nil) {
		t.Error("存在等于 beta 的取值时，不等于条件不应成立")
	}
	if !cr.Matches(req("GET", "/"), nil) {
		t.Error("字段缺失时否定类条件应成立")
	}
}

func TestMatches_ExistsAndNotExists(t *testing.T) {
	exists := mustCompile(t, ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldHeader, Key: "X-Api-Token", Op: model.CCOpExists,
	}))
	notExists := mustCompile(t, ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldHeader, Key: "X-Api-Token", Op: model.CCOpNotExists,
	}))

	withHeader := req("GET", "/")
	withHeader.Header.Set("X-Api-Token", "abc")

	if !exists.Matches(withHeader, nil) || exists.Matches(req("GET", "/"), nil) {
		t.Error("exists 判定不正确")
	}
	if notExists.Matches(withHeader, nil) || !notExists.Matches(req("GET", "/"), nil) {
		t.Error("not_exists 判定不正确")
	}
}

func TestMatches_NumericOps(t *testing.T) {
	cr := mustCompile(t, ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldStatusCode, Op: model.CCOpBetween, Value: model.CCCondVal{"400", "499"},
	}))
	if !cr.Matches(req("GET", "/"), &innerbean.WebLog{STATUS_CODE: 404}) {
		t.Error("404 应落在 400~499 之间")
	}
	if cr.Matches(req("GET", "/"), &innerbean.WebLog{STATUS_CODE: 200}) {
		t.Error("200 不应落在 400~499 之间")
	}
}

func TestCompile_RejectsBadRegexAndReportsResponsePhase(t *testing.T) {
	_, err := Compile(ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldURI, Op: model.CCOpRegex, Value: model.CCCondVal{"([a-z"},
	}))
	if err == nil {
		t.Error("非法正则应在编译期被拒绝，而不是留到请求期才失败")
	}

	cr := mustCompile(t, ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldStatusCode, Op: model.CCOpEq, Value: model.CCCondVal{"404"},
	}))
	if !cr.NeedsResponsePhase() {
		t.Error("引用响应期字段的规则应被标记为需要响应期判定")
	}
}

func TestInCountScope(t *testing.T) {
	dynamic := mustCompile(t, &model.AntiCCRule{
		MatchMode: model.CCMatchModeAll, CountScope: model.CCCountScopeDynamic,
	})
	if !dynamic.InCountScope(req("GET", "/api/list")) {
		t.Error("动态请求应计入")
	}
	if dynamic.InCountScope(req("GET", "/assets/app.css")) {
		t.Error("静态资源不应计入")
	}

	all := mustCompile(t, &model.AntiCCRule{
		MatchMode: model.CCMatchModeAll, CountScope: model.CCCountScopeAll,
	})
	if !all.InCountScope(req("GET", "/assets/app.css")) {
		t.Error("全部请求口径下静态资源也应计入")
	}

	doc := mustCompile(t, &model.AntiCCRule{
		MatchMode: model.CCMatchModeAll, CountScope: model.CCCountScopeDocument,
	})
	pageReq := req("GET", "/")
	pageReq.Header.Set("Sec-Fetch-Dest", "document")
	assetReq := req("GET", "/app.js")
	assetReq.Header.Set("Sec-Fetch-Dest", "script")
	if !doc.InCountScope(pageReq) || doc.InCountScope(assetReq) {
		t.Error("文档口径应只统计页面文档请求")
	}
}

func TestMatches_TruncatesOverlongValue(t *testing.T) {
	cr := mustCompile(t, ruleWithConds(t, model.MatchCondition{
		Field: model.CCFieldHeader, Key: "X-Big", Op: model.CCOpContains, Value: model.CCCondVal{"needle"},
	}))
	r := req("GET", "/")
	// 把关键字放在截断长度之外：超长取值被截断，是限长带来的预期代价
	r.Header.Set("X-Big", strings.Repeat("a", maxFieldValueLen+10)+"needle")
	if cr.Matches(r, nil) {
		t.Error("超出截断长度的内容不应参与匹配")
	}
}

// —— 统计维度 ——

func TestDimValue_IPAndComposite(t *testing.T) {
	ip := mustCompile(t, &model.AntiCCRule{MatchMode: model.CCMatchModeAll, StatDim: model.CCStatDimIP})
	if v, fb := ip.DimValue(req("GET", "/a"), nil, "1.2.3.4"); v != "1.2.3.4" || fb {
		t.Errorf("IP 维度取值不正确: %s fallback=%v", v, fb)
	}

	ipURI := mustCompile(t, &model.AntiCCRule{MatchMode: model.CCMatchModeAll, StatDim: model.CCStatDimIPURI})
	if v, _ := ipURI.DimValue(req("GET", "/a"), nil, "1.2.3.4"); v != "1.2.3.4|/a" {
		t.Errorf("IP+URL 维度取值不正确: %s", v)
	}

	total := mustCompile(t, &model.AntiCCRule{MatchMode: model.CCMatchModeAll, StatDim: model.CCStatDimHostTotal})
	a, _ := total.DimValue(req("GET", "/a"), nil, "1.1.1.1")
	b, _ := total.DimValue(req("GET", "/b"), nil, "2.2.2.2")
	if a != b {
		t.Error("站点总量维度下所有请求应共用同一个计数桶")
	}
}

// 维度字段取不到值时必须回退按 IP —— 否则所有没带该字段的访客会共用一个计数桶被一起限死。
func TestDimValue_FallsBackToIPWhenFieldMissing(t *testing.T) {
	cr := mustCompile(t, &model.AntiCCRule{
		MatchMode: model.CCMatchModeAll, StatDim: model.CCStatDimCookie, StatDimField: "uid",
	})

	withCookie := req("GET", "/")
	withCookie.AddCookie(&http.Cookie{Name: "uid", Value: "u-1001"})
	if v, fb := cr.DimValue(withCookie, nil, "1.2.3.4"); v != "u-1001" || fb {
		t.Errorf("带 cookie 时应按 cookie 取值: %s fallback=%v", v, fb)
	}

	v1, fb1 := cr.DimValue(req("GET", "/"), nil, "1.1.1.1")
	v2, fb2 := cr.DimValue(req("GET", "/"), nil, "2.2.2.2")
	if !fb1 || !fb2 {
		t.Error("字段缺失时应标记为已回退")
	}
	if v1 == v2 {
		t.Error("回退后必须按各自 IP 分开计数，不能都归到同一个取值上")
	}
}

func TestDimValue_BodyField(t *testing.T) {
	cr := mustCompile(t, &model.AntiCCRule{
		MatchMode: model.CCMatchModeAll, StatDim: model.CCStatDimBody, StatDimField: "uid",
	})
	log := &innerbean.WebLog{
		BodyFields: []string{"name", "uid"},
		BodyValues: []string{"tom", "u-2002"},
	}
	if v, fb := cr.DimValue(req("POST", "/"), log, "1.2.3.4"); v != "u-2002" || fb {
		t.Errorf("应取 JSON 请求体里的 uid: %s fallback=%v", v, fb)
	}
}
