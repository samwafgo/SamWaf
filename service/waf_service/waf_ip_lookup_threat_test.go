package waf_service

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafenginecore/ipset"
	"SamWaf/waftask/threatip"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupThreatLookupTestDB 建包含威胁情报渠道/快照/排除/ip_tags 全套表的临时库，隔离全局态。
func setupThreatLookupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "threat_lookup_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(
		&model.ThreatIPChannel{}, &model.ThreatIPSnapshot{}, &model.ThreatIPExclude{},
		&model.IPTag{}, &model.IPGroup{}, &model.IPGroupItem{},
		&model.IPBlockList{}, &model.IPAllowList{}, &model.Hosts{}, &model.FirewallIPBlock{},
	); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	oldDB, oldStatsDB := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_STATS_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	oldTagDB := global.GDATA_IP_TAG_DB
	oldExclude := WafThreatIPExcludeServiceApp.load()
	oldIndex := ipset.GetGlobalThreatIndex()

	global.GWAF_LOCAL_DB = db
	global.GWAF_LOCAL_STATS_DB = db
	global.GDATA_IP_TAG_DB = 0
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-threat-lookup"
	WafThreatIPExcludeServiceApp.Invalidate()
	ipset.SetGlobalThreatIndex(nil)

	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_LOCAL_STATS_DB = oldStatsDB
		global.GDATA_IP_TAG_DB = oldTagDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		WafThreatIPExcludeServiceApp.store(oldExclude)
		ipset.SetGlobalThreatIndex(oldIndex)
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func seedThreatChannel(t *testing.T, db *gorm.DB, code, name, landTarget string, enable int, ips []string) {
	t.Helper()
	payload, sha, cnt, err := threatip.EncodeSnapshot(ips)
	if err != nil {
		t.Fatalf("编码快照失败: %v", err)
	}
	if err := db.Create(&model.ThreatIPChannel{
		BaseOrm:    newLookupBase("ch-" + code),
		Code:       code,
		Name:       name,
		LandTarget: landTarget,
		Enable:     enable,
	}).Error; err != nil {
		t.Fatalf("写入渠道失败: %v", err)
	}
	if err := db.Create(&model.ThreatIPSnapshot{
		BaseOrm:     newLookupBase("snap-" + code),
		ChannelCode: code,
		Count:       cnt,
		Payload:     payload,
		Sha256:      sha,
	}).Error; err != nil {
		t.Fatalf("写入快照失败: %v", err)
	}
}

// TestLookupThreatIP_SystemOnlyNotDropped 回归 R2：
// 仅落地到 system（系统防火墙）层的启用渠道，WAF 并集不含它，但「IP策略命中查询」必须能查到并标 SystemLayer=true。
func TestLookupThreatIP_SystemOnlyNotDropped(t *testing.T) {
	db := setupThreatLookupTestDB(t)
	seedThreatChannel(t, db, "sys_only", "System Feed", model.ThreatLandSystem, 1, []string{"198.51.100.0/24"})

	WafThreatIPServiceApp.RebuildWAFUnion()

	// WAF 层并集不能包含仅 system 渠道，避免系统层渠道误入 WAF 应用层拦截
	if ipset.GetGlobalThreatMatcher() != nil && ipset.GetGlobalThreatMatcher().ContainsStr("198.51.100.7") {
		t.Fatal("仅 system 渠道不应进入 WAFUnion")
	}

	resp, err := WafIPLookupServiceApp.Lookup("198.51.100.7", []string{srcThreatIP})
	if err != nil {
		t.Fatalf("Lookup 失败: %v", err)
	}
	if len(resp.Hits) != 1 {
		t.Fatalf("期望命中 1 条系统层威胁情报，实际 %+v", resp.Hits)
	}
	h := resp.Hits[0]
	if h.Source != srcThreatIP || h.Scope != "System Feed" || h.Matched != "198.51.100.0/24" || !h.SystemLayer || h.Effect != "block" {
		t.Fatalf("命中内容不符合预期: %+v", h)
	}
}

// TestLookupThreatIP_MultiChannelAllShown 同一 IP 同时落在多个启用渠道时，查询弹窗应全部展示。
func TestLookupThreatIP_MultiChannelAllShown(t *testing.T) {
	db := setupThreatLookupTestDB(t)
	seedThreatChannel(t, db, "firehol", "FireHOL Level1", model.ThreatLandBoth, 1, []string{"203.0.113.0/24"})
	seedThreatChannel(t, db, "ipsum", "IPsum", model.ThreatLandWAF, 1, []string{"203.0.113.8"})

	WafThreatIPServiceApp.RebuildWAFUnion()

	resp, err := WafIPLookupServiceApp.Lookup("203.0.113.8", []string{srcThreatIP})
	if err != nil {
		t.Fatalf("Lookup 失败: %v", err)
	}
	if len(resp.Hits) != 2 {
		t.Fatalf("期望命中 2 家渠道，实际 %+v", resp.Hits)
	}
	if resp.Hits[0].Scope != "FireHOL Level1" || resp.Hits[0].Matched != "203.0.113.0/24" || !resp.Hits[0].SystemLayer {
		t.Fatalf("第 1 条命中不对: %+v", resp.Hits[0])
	}
	if resp.Hits[1].Scope != "IPsum" || resp.Hits[1].Matched != "203.0.113.8" || resp.Hits[1].SystemLayer {
		t.Fatalf("第 2 条命中不对: %+v", resp.Hits[1])
	}
}

// TestLookupThreatIP_BuiltinAutoExcludeOnlyWhenInRawSnapshot 回归 R4：
// 内置自动排除（如内网段/管理白名单）只在该 IP 确实存在于某启用渠道原始快照里时才提示，
// 查不在任何快照里的普通内网 IP 必须零噪音。
func TestLookupThreatIP_BuiltinAutoExcludeOnlyWhenInRawSnapshot(t *testing.T) {
	db := setupThreatLookupTestDB(t)
	// 注入一条内置自动排除条目（Id==""，模拟内网段/管理端白名单）
	pat, err := ipset.ParsePatternLenient("10.10.0.0/16")
	if err != nil {
		t.Fatalf("解析网段失败: %v", err)
	}
	WafThreatIPExcludeServiceApp.store(&ExcludeSet{
		entries: []excludeEntry{{
			Id:     "",
			Raw:    "10.10.0.0/16",
			Reason: "内置内网段豁免",
			pat:    pat,
			exact:  true,
		}},
		fast: ipset.BuildMatchSet([]string{"10.10.0.0/16"}),
		sha:  "test-builtin-sha",
	})

	seedThreatChannel(t, db, "ustc", "USTC blackip", model.ThreatLandWAF, 1, []string{"10.10.1.5"})
	WafThreatIPServiceApp.RebuildWAFUnion()

	// 1. 在原始快照内的 10.10.1.5：已被内置规则剔除，应给出 threat_exclude 豁免说明且指名渠道
	respIn, err := WafIPLookupServiceApp.Lookup("10.10.1.5", []string{srcThreatIP})
	if err != nil {
		t.Fatalf("Lookup 失败: %v", err)
	}
	if len(respIn.Hits) != 1 || respIn.Hits[0].Source != srcThreatExclude || respIn.Hits[0].Effect != "allow" || !strings.Contains(respIn.Hits[0].Detail, "USTC blackip") {
		t.Fatalf("快照内被内置豁免的 IP 应提示豁免及来源渠道，实际 %+v", respIn.Hits)
	}

	// 2. 不在任何快照里的 10.10.2.9：必须零噪音，不报内置排除
	respOut, err := WafIPLookupServiceApp.Lookup("10.10.2.9", []string{srcThreatIP})
	if err != nil {
		t.Fatalf("Lookup 失败: %v", err)
	}
	if len(respOut.Hits) != 0 {
		t.Fatalf("不在任何威胁快照里的内网 IP 不应报内置排除噪音，实际 %+v", respOut.Hits)
	}
}

// TestLookupThreatIP_DisabledChannelAndHistoryTags 回归 R3（Issue #1081 核心场景）：
// 1) IP 仍在已停用渠道快照里 → 报 Effect="none" 的已停用提示，不误报为拦截；
// 2) IP 已从情报源退榜但 ip_tags 留存历史标签 → 返回 HistoryThreatTags，且不造假命中。
func TestLookupThreatIP_DisabledChannelAndHistoryTags(t *testing.T) {
	db := setupThreatLookupTestDB(t)
	seedThreatChannel(t, db, "old_feed", "Old Feed", model.ThreatLandWAF, 0, []string{"34.38.88.176"})
	WafThreatIPServiceApp.RebuildWAFUnion()

	hitTime := time.Date(2026, 11, 5, 14, 22, 0, 0, time.Local)
	for _, row := range []model.IPTag{
		{
			BaseOrm: func() model.IPTag {
				b := newLookupBase("t1")
				b.UPDATE_TIME = customtype.JsonTime(hitTime)
				return model.IPTag{BaseOrm: b}
			}().BaseOrm,
			IP:    "34.38.88.176",
			IPTag: "威胁情报IP:FireHOL Level1",
			Cnt:   800,
		},
		{
			BaseOrm: func() model.IPTag {
				b := newLookupBase("t2")
				b.UPDATE_TIME = customtype.JsonTime(hitTime.Add(-time.Hour))
				return model.IPTag{BaseOrm: b}
			}().BaseOrm,
			IP:    "34.38.88.176",
			IPTag: "威胁情报IP",
			Cnt:   295,
		},
		{
			// 非威胁情报标签不应混入 HistoryThreatTags
			BaseOrm: newLookupBase("t3"),
			IP:      "34.38.88.176",
			IPTag:   "SQL注入检测",
			Cnt:     50,
		},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("写入 ip_tags 失败: %v", err)
		}
	}

	resp, err := WafIPLookupServiceApp.Lookup("34.38.88.176", []string{srcThreatIP})
	if err != nil {
		t.Fatalf("Lookup 失败: %v", err)
	}
	// 已停用渠道应给 Effect="none" 的提示，绝不能是 block
	if len(resp.Hits) != 1 || resp.Hits[0].Effect != "none" || resp.Hits[0].Scope != "Old Feed" {
		t.Fatalf("已停用渠道应以 Effect=none 展示，实际 %+v", resp.Hits)
	}
	// 历史威胁情报标签按次数倒序返回，仅含威胁情报标签
	if len(resp.HistoryThreatTags) != 2 {
		t.Fatalf("期望 2 条历史威胁标签，实际 %+v", resp.HistoryThreatTags)
	}
	if resp.HistoryThreatTags[0].Tag != "威胁情报IP:FireHOL Level1" || resp.HistoryThreatTags[0].Count != 800 || resp.HistoryThreatTags[0].LatestTime != "2026-11-05 14:22:00" {
		t.Fatalf("第 1 条历史标签不对: %+v", resp.HistoryThreatTags[0])
	}
	if resp.HistoryThreatTags[1].Tag != "威胁情报IP" || resp.HistoryThreatTags[1].Count != 295 {
		t.Fatalf("第 2 条历史标签不对: %+v", resp.HistoryThreatTags[1])
	}
}
