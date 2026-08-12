package wafenginecore

import (
	"SamWaf/innerbean"
	"testing"
)

// 地区封禁没有独立模块，走的是自定义规则。地区库缺失时 COUNTRY 会是"未知"，
// `MF.COUNTRY != "中国"` 恒成立，会把访客整片误杀。这批用例锁住"地区不可判定即放行"的语义。

func TestIsGeoRule(t *testing.T) {
	cases := []struct {
		name string
		grl  string
		want bool
	}{
		{"COUNTRY 比较", `rule R1 "x" { when MF.COUNTRY != "中国" then RF.Deny(); }`, true},
		{"PROVINCE 比较", `rule R1 "x" { when MF.PROVINCE == "广东" then RF.Deny(); }`, true},
		{"CITY 比较", `rule R1 "x" { when MF.CITY == "深圳" then RF.Allow(); }`, true},
		{"带空格的写法", `rule R1 "x" { when MF . COUNTRY != "中国" then RF.Deny(); }`, true},
		{"组合条件里含地区", `rule R1 "x" { when MF.COUNTRY != "中国" && MF.URL.HasPrefix("/login") == true then RF.Deny(); }`, true},
		{"与地区无关", `rule R1 "x" { when MF.URL == "/admin" then RF.Deny(); }`, false},
		// 规则描述/字符串字面量里出现 COUNTRY 只是文字，不是条件，不能算地区规则
		{"字符串里出现COUNTRY", `rule R1 "按 COUNTRY 统计" { when MF.URL == "/x?a=MF.COUNTRY" then RF.Deny(); }`, false},
		{"前缀不完整不算", `rule R1 "x" { when MF.COUNTRYCODE == "CN" then RF.Deny(); }`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isGeoRule(c.grl); got != c.want {
				t.Fatalf("isGeoRule=%v want=%v\n%s", got, c.want, c.grl)
			}
		})
	}
}

// 地区不可判定时，"拦截海外访问"这条官方模板规则必须不生效（放行）
func TestGeoUnresolvedDropsOverseasDenyRule(t *testing.T) {
	rh := buildRuleHelper(t, `
rule Rtest001 "拦截海外访问" salience 10 {
    when MF.COUNTRY != "中国"
    then RF.Deny();
}`)

	// 地区可判定：正常命中并拦截
	logResolved := &innerbean.WebLog{URL: "/", COUNTRY: "未知", GeoUnresolved: false}
	if res := matchRules(rh, logResolved, ""); !res.Matched {
		t.Fatal("地区可判定时应命中拦截规则")
	}

	// 地区不可判定：同样的请求必须不再命中
	logUnresolved := &innerbean.WebLog{URL: "/", COUNTRY: "未知", GeoUnresolved: true}
	if res := matchRules(rh, logUnresolved, ""); res.Matched {
		t.Fatalf("地区不可判定时应放行，却命中了: %s", res.Title)
	}
}

// 剔除只针对地区规则，非地区规则不受影响
func TestGeoUnresolvedKeepsNonGeoRule(t *testing.T) {
	rh := buildRuleHelper(t, `
rule Rtest001 "拦截后台路径" salience 10 {
    when MF.URL == "/admin"
    then RF.Deny();
}`)

	log := &innerbean.WebLog{URL: "/admin", COUNTRY: "未知", GeoUnresolved: true}
	if res := matchRules(rh, log, ""); !res.Matched {
		t.Fatal("非地区规则不应被地区标志位影响")
	}
}

// 地区放行规则也一并剔除：语义是"这条规则这次不参与判定"，
// 而不是"这次判成了放行"——否则会反过来让本该被别的规则拦下的请求溜过去。
func TestGeoUnresolvedDropsGeoAllowRuleToo(t *testing.T) {
	rh := buildRuleHelper(t, `
rule Rtest001 "国内放行" salience 10 {
    when MF.COUNTRY == "未知"
    then RF.Allow();
}`)

	log := &innerbean.WebLog{URL: "/", COUNTRY: "未知", GeoUnresolved: true}
	if res := matchRules(rh, log, ""); res.Matched {
		t.Fatalf("地区不可判定时地区放行规则也应剔除，却命中了: %s", res.Title)
	}
}
