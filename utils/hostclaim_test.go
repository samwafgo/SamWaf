package utils

import (
	"SamWaf/model"
	"testing"
)

func TestHostRouteClaims_BindMoreAndAutoJump(t *testing.T) {
	h := model.Hosts{
		Code:           "A",
		Host:           "Example.COM",
		Port:           443,
		AutoJumpHTTPS:  1,
		BindMoreHost:   "WWW.Alias.COM\n例子.com",
		BindMorePort:   "8080",
	}
	claims := HostRouteClaims(h)
	need := map[string]bool{
		"example.com:443":           false,
		"example.com:80":            false,
		"example.com:8080":          false,
		"www.alias.com:443":         false,
		"www.alias.com:80":          false,
		"xn--fsqu00a.com:443":       false,
	}
	for _, c := range claims {
		if c.AnyPort {
			continue
		}
		key := FormatRouteClaim(c)
		if _, ok := need[key]; ok {
			need[key] = true
		}
	}
	for k, ok := range need {
		if !ok {
			t.Errorf("missing claim %s in %+v", k, claims)
		}
	}
}

func TestFindRouteClaimConflict_BindMoreHost(t *testing.T) {
	a := model.Hosts{Code: "A", Host: "shared.example.com", Port: 80, Nickname: "站点A"}
	b := model.Hosts{Code: "B", Host: "other.example.com", Port: 80, BindMoreHost: "SHARED.example.com"}
	other, claim, found := FindRouteClaimConflict("B", b, []model.Hosts{a, b})
	if !found {
		t.Fatal("B 的 BindMoreHost 应与 A 的主域名冲突")
	}
	if other.Code != "A" {
		t.Errorf("conflict owner=%q", other.Code)
	}
	if claim.Domain != "shared.example.com" || claim.Port != 80 {
		t.Errorf("claim=%+v", claim)
	}
}

func TestFindRouteClaimConflict_AutoJump80(t *testing.T) {
	a := model.Hosts{Code: "A", Host: "shared.example.com", Port: 80}
	b := model.Hosts{Code: "B", Host: "shared.example.com", Port: 443, AutoJumpHTTPS: 1}
	_, _, found := FindRouteClaimConflict("B", b, []model.Hosts{a})
	if !found {
		t.Fatal("同名 443+AutoJumpHTTPS 应占用 :80 而与 A 冲突")
	}
	_, _, found = FindRouteClaimConflict("B", model.Hosts{Code: "B", Host: "shared.example.com", Port: 443}, []model.Hosts{a})
	if found {
		t.Fatal("同名不同端口、无 AutoJump 不应冲突")
	}
}

func TestFindRouteClaimConflict_CaseAndIDN(t *testing.T) {
	a := model.Hosts{Code: "A", Host: "例子.com", Port: 80}
	b := model.Hosts{Code: "B", Host: "xn--fsqu00a.com", Port: 80}
	_, _, found := FindRouteClaimConflict("B", b, []model.Hosts{a})
	if !found {
		t.Fatal("中文与 Punycode 应视为同一域名")
	}
	c := model.Hosts{Code: "C", Host: "EXAMPLE.com", Port: 80}
	d := model.Hosts{Code: "D", Host: "example.com", Port: 80}
	_, _, found = FindRouteClaimConflict("D", d, []model.Hosts{c})
	if !found {
		t.Fatal("大小写应视为同一域名")
	}
}

func TestFindRouteClaimConflict_Unrestricted(t *testing.T) {
	a := model.Hosts{Code: "A", Host: "shared.example.com", Port: 80, UnrestrictedPort: 1}
	b := model.Hosts{Code: "B", Host: "shared.example.com", Port: 443}
	_, claim, found := FindRouteClaimConflict("B", b, []model.Hosts{a})
	if !found {
		t.Fatal("宽松端口应占用该域名所有端口")
	}
	_ = claim
}

func TestFindRouteClaimConflict_ExcludeSelfAndGlobal(t *testing.T) {
	g := model.Hosts{Code: "G", Host: "example.com", Port: 80, GLOBAL_HOST: 1}
	a := model.Hosts{Code: "A", Host: "example.com", Port: 80}
	_, _, found := FindRouteClaimConflict("A", a, []model.Hosts{g, a})
	if found {
		t.Fatal("排除自身且全局站不参与互斥")
	}
}

func TestValidateHostNamesNoDuplicate_MainAndBindMoreIDN(t *testing.T) {
	h := model.Hosts{Host: "测试.com", BindMoreHost: "xn--0zwm56d.com"}
	if err := ValidateHostNamesNoDuplicate(h); err == nil {
		t.Fatal("主域名与 BindMoreHost 中文/Punycode 重复应拒绝")
	}
}

func TestValidateHostNamesNoDuplicate_BindMoreOnly(t *testing.T) {
	h := model.Hosts{Host: "www.example.com", BindMoreHost: "测试.com\nxn--0zwm56d.com"}
	if err := ValidateHostNamesNoDuplicate(h); err == nil {
		t.Fatal("BindMoreHost 内中文/Punycode 重复应拒绝")
	}
}

func TestValidateHostNamesNoDuplicate_CaseInBindMore(t *testing.T) {
	h := model.Hosts{Host: "Example.COM", BindMoreHost: "example.com"}
	if err := ValidateHostNamesNoDuplicate(h); err == nil {
		t.Fatal("大小写重复应拒绝")
	}
}

func TestValidateHostNamesNoDuplicate_OK(t *testing.T) {
	h := model.Hosts{Host: "a.example.com", BindMoreHost: "b.example.com\n例子.net"}
	if err := ValidateHostNamesNoDuplicate(h); err != nil {
		t.Fatal(err)
	}
}
