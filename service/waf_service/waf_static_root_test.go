package waf_service

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
)

func withStaticAllowed(t *testing.T) string {
	t.Helper()
	allowed := t.TempDir()
	orig := global.GCONFIG_STATIC_SITE_ALLOWED_DIRS
	global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = allowed
	t.Cleanup(func() { global.GCONFIG_STATIC_SITE_ALLOWED_DIRS = orig })
	return allowed
}

func staticJSON(t *testing.T, enable int, dir string, mutate func(*model.StaticSiteConfig)) string {
	t.Helper()
	cfg := model.StaticSiteConfig{
		IsEnableStaticSite:  enable,
		StaticSitePath:      dir,
		StaticSitePrefix:    "/",
		SensitivePaths:      model.StaticSiteDefaultSensitivePaths,
		SensitiveExtensions: model.StaticSiteDefaultSensitiveExtensions,
		AllowedExtensions:   model.StaticSiteDefaultAllowedExtensions,
		SensitivePatterns:   model.StaticSiteDefaultSensitivePatterns,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCheckHostStaticSiteChange(t *testing.T) {
	allowed := withStaticAllowed(t)
	outside := t.TempDir()
	dataDir := filepath.Join(absProgramDir(t), "data")
	cases := []struct {
		name        string
		newJSON     string
		oldJSON     string
		wantChecked bool
		wantCode    string
	}{
		{"disabled not checked", staticJSON(t, 0, outside, nil), "", false, ""},
		{"empty json not checked", "", "", false, ""},
		{"add allowed", staticJSON(t, 1, allowed, nil), "", true, ""},
		{"add outside", staticJSON(t, 1, outside, nil), "", true, utils.StaticRootNotAllowed},
		{"add data dir", staticJSON(t, 1, dataDir, nil), "", true, utils.StaticRootProtected},
		{"unchanged legacy kept", staticJSON(t, 1, outside, nil), staticJSON(t, 1, outside, nil), false, ""},
		{"unchanged with trailing sep", staticJSON(t, 1, outside+string(filepath.Separator), nil), staticJSON(t, 1, outside, nil), false, ""},
		{"legacy re-enabled checked", staticJSON(t, 1, outside, nil), staticJSON(t, 0, outside, nil), true, utils.StaticRootNotAllowed},
		{"path changed checked", staticJSON(t, 1, filepath.Join(outside, "x"), nil), staticJSON(t, 1, outside, nil), true, utils.StaticRootNotAllowed},
		{"old json broken checked", staticJSON(t, 1, outside, nil), "{bad", true, utils.StaticRootNotAllowed},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			chk := CheckHostStaticSiteChange(tt.newJSON, tt.oldJSON)
			if chk.Checked != tt.wantChecked {
				t.Fatalf("checked=%v want %v", chk.Checked, tt.wantChecked)
			}
			if got := utils.StaticRootErrorCode(chk.Err); got != tt.wantCode {
				t.Fatalf("code=%q want %q err=%v", got, tt.wantCode, chk.Err)
			}
		})
	}
}

func TestCheckPathRuleStaticChange(t *testing.T) {
	allowed := withStaticAllowed(t)
	outside := t.TempDir()
	legacy := &model.HostPathRule{BaseOrm: baseorm.BaseOrm{Id: "r1"}, TargetType: model.PathRuleTargetStatic, StaticRoot: outside}
	proxy := &model.HostPathRule{BaseOrm: baseorm.BaseOrm{Id: "r2"}, TargetType: 1, StaticRoot: outside}
	notFound := &model.HostPathRule{}
	cases := []struct {
		name        string
		targetType  int
		root        string
		old         *model.HostPathRule
		wantChecked bool
		wantCode    string
	}{
		{"proxy not checked", 1, outside, nil, false, ""},
		{"add allowed", model.PathRuleTargetStatic, allowed, nil, true, ""},
		{"add outside", model.PathRuleTargetStatic, outside, nil, true, utils.StaticRootNotAllowed},
		{"unchanged legacy kept", model.PathRuleTargetStatic, outside, legacy, false, ""},
		{"switched to static checked", model.PathRuleTargetStatic, outside, proxy, true, utils.StaticRootNotAllowed},
		{"missing old checked", model.PathRuleTargetStatic, outside, notFound, true, utils.StaticRootNotAllowed},
		{"relative rejected", model.PathRuleTargetStatic, "www", nil, true, utils.StaticRootInvalid},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			chk := CheckPathRuleStaticChange(tt.targetType, tt.root, tt.old)
			if chk.Checked != tt.wantChecked {
				t.Fatalf("checked=%v want %v", chk.Checked, tt.wantChecked)
			}
			if got := utils.StaticRootErrorCode(chk.Err); got != tt.wantCode {
				t.Fatalf("code=%q want %q err=%v", got, tt.wantCode, chk.Err)
			}
		})
	}
}

func TestCollectStaticRootFindings(t *testing.T) {
	allowed := withStaticAllowed(t)
	outside := t.TempDir()
	hosts := []model.Hosts{
		{Code: "ok", Host: "ok.test", StaticSiteJSON: staticJSON(t, 1, allowed, nil)},
		{Code: "off", Host: "off.test", StaticSiteJSON: staticJSON(t, 0, outside, nil)},
		{Code: "out", Host: "out.test", StaticSiteJSON: staticJSON(t, 1, outside, nil)},
		{Code: "list", Host: "list.test", StaticSiteJSON: staticJSON(t, 1, allowed, func(c *model.StaticSiteConfig) {
			c.SensitiveExtensions = ".key,.pem"
			c.AllowedExtensions = model.StaticSiteDefaultAllowedExtensions + ",.yml"
		})},
		{Code: "emptylists", Host: "e.test", StaticSiteJSON: staticJSON(t, 1, allowed, func(c *model.StaticSiteConfig) {
			c.SensitivePaths, c.SensitiveExtensions, c.AllowedExtensions, c.SensitivePatterns = "", "", "", ""
		})},
		{Code: "ruleonly", Host: "r.test", StaticSiteJSON: staticJSON(t, 0, "", func(c *model.StaticSiteConfig) {
			c.SensitivePatterns = `(?i).env`
		})},
	}
	rules := []model.HostPathRule{
		{BaseOrm: baseorm.BaseOrm{Id: "pr1"}, HostCode: "ruleonly", Path: "/s", TargetType: model.PathRuleTargetStatic, StaticRoot: filepath.Join(absProgramDir(t), "conf")},
		{BaseOrm: baseorm.BaseOrm{Id: "pr2"}, HostCode: "ok", Path: "/a", TargetType: model.PathRuleTargetStatic, StaticRoot: allowed},
	}
	got := map[string]staticRootFinding{}
	for _, f := range collectStaticRootFindings(hosts, rules) {
		got[f.ObjectType+"/"+f.ObjectID+"/"+f.Kind] = f
	}
	want := []string{
		"host/out/" + utils.StaticRootNotAllowed,
		"host/list/" + staticReviewListReduced,
		"path_rule/pr1/" + utils.StaticRootProtected,
		"host/ruleonly/" + staticReviewListReduced,
	}
	if len(got) != len(want) {
		t.Fatalf("findings=%v want %v", keys(got), want)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing %s in %v", k, keys(got))
		}
	}
	msg := got["host/list/"+staticReviewListReduced].Message
	if !strings.Contains(msg, ".yml") || !strings.Contains(msg, ".p12") {
		t.Fatalf("list message: %s", msg)
	}
	a := got["host/out/"+utils.StaticRootNotAllowed]
	b := a
	b.Path = outside + "x"
	if a.fingerprint() == b.fingerprint() || a.fingerprint() != got["host/out/"+utils.StaticRootNotAllowed].fingerprint() {
		t.Fatal("fingerprint must be stable and change with path")
	}
}

func keys(m map[string]staticRootFinding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func absProgramDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(utils.GetCurrentDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestStaticRootReviewPersistsOnce(t *testing.T) {
	db := setupHostGroupTestDB(t)
	if err := db.AutoMigrate(&model.HostPathRule{}, &model.SecurityAuditLog{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	withStaticAllowed(t)
	h := model.Hosts{BaseOrm: baseorm.BaseOrm{Id: "site-id"}, Code: "site-code", Host: "fixture.test", StaticSiteJSON: staticJSON(t, 1, dir, nil)}
	if err := db.Create(&h).Error; err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{1, 0} {
		n, err := reviewStaticRoots(db, db)
		if err != nil || n != want {
			t.Fatalf("review count=%d want=%d err=%v", n, want, err)
		}
	}
	var audit model.SecurityAuditLog
	if err := db.Where("event = ?", model.AuditEventConfigStaticRootReview).First(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if audit.HostCode != h.Code || audit.Category != model.AuditCategoryConfig || len(audit.Fingerprint) != 64 {
		t.Fatal("unexpected audit record")
	}
	var stored model.Hosts
	if err := db.Where("id = ?", h.Id).First(&stored).Error; err != nil || stored.StaticSiteJSON != h.StaticSiteJSON {
		t.Fatal("stored config changed", err)
	}
}
