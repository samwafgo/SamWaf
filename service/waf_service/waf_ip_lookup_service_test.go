package waf_service

import (
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupIPLookupTestDB 建临时库并接管全局 DB，用例结束后还原
func setupIPLookupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "iplookup_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(
		&model.IPGroup{}, &model.IPGroupItem{}, &model.IPBlockList{},
		&model.IPAllowList{}, &model.Hosts{}, &model.FirewallIPBlock{},
	); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-iplookup"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// newLookupBase 与 crossdb 套件里的 newBase 同名会撞（那边无 build tag 隔离），故独立命名
func newLookupBase(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{Id: id, USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID}
}

// TestLookupMatchesCIDR 网段必须能命中：用户填的是 1.2.3.0/24，查 1.2.3.4 得算命中。
// 这条最容易写错成字符串相等，一旦退化就会误报「这个IP不在黑名单里」。
func TestLookupMatchesCIDR(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.Hosts{BaseOrm: newLookupBase("h1"), Code: "hostA", Host: "www.demo.com"})
	db.Create(&model.IPBlockList{BaseOrm: newLookupBase("b1"), HostCode: "hostA", Ip: "1.2.3.0/24", Remarks: "网段封禁"})

	resp, err := WafIPLookupServiceApp.Lookup("1.2.3.4", nil)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(resp.Hits) != 1 {
		t.Fatalf("期望命中1条，实际 %d 条", len(resp.Hits))
	}
	h := resp.Hits[0]
	if h.Source != srcIPBlack || h.Effect != "block" {
		t.Fatalf("来源/效果不对: %+v", h)
	}
	if h.Matched != "1.2.3.0/24" {
		t.Fatalf("应回显实际命中的那条规则，实际 %q", h.Matched)
	}
	if h.Scope != "www.demo.com" {
		t.Fatalf("host_code 应翻成域名，实际 %q", h.Scope)
	}
}

// TestLookupGlobalScope host_code 为空表示全局网站，必须标成「全局」，
// 否则用户会以为这条只影响某一个站点
func TestLookupGlobalScope(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.IPAllowList{BaseOrm: newLookupBase("a1"), HostCode: "", Ip: "10.0.0.1"})

	resp, _ := WafIPLookupServiceApp.Lookup("10.0.0.1", nil)
	if len(resp.Hits) != 1 || resp.Hits[0].Scope != "全局" {
		t.Fatalf("空 host_code 应显示为全局，实际 %+v", resp.Hits)
	}
	// 全局站点其实是 hosts 表里一条 host="全局网站" 的普通记录，走站点名即可
	db.Create(&model.Hosts{BaseOrm: newLookupBase("hg"), Code: "uuid-global", Host: "全局网站"})
	db.Create(&model.IPAllowList{BaseOrm: newLookupBase("a2"), HostCode: "uuid-global", Ip: "10.0.0.2"})
	if r2, _ := WafIPLookupServiceApp.Lookup("10.0.0.2", nil); r2.Hits[0].Scope != "全局网站" {
		t.Fatalf("全局站点应显示站点名，实际 %q", r2.Hits[0].Scope)
	}
	// 指向已删除站点的名单不会生效，必须标出来而不是显示一串 uuid
	db.Create(&model.IPAllowList{BaseOrm: newLookupBase("a3"), HostCode: "gone-uuid", Ip: "10.0.0.3"})
	if r3, _ := WafIPLookupServiceApp.Lookup("10.0.0.3", nil); !strings.Contains(r3.Hits[0].Scope, "不生效") {
		t.Fatalf("站点不存在应提示不生效，实际 %q", r3.Hits[0].Scope)
	}
	if resp.Hits[0].Effect != "allow" {
		t.Fatalf("白名单效果应为 allow，实际 %q", resp.Hits[0].Effect)
	}
}

// TestLookupGroupRefEffect IP组本身不决定放行/拦截，取决于谁引用了它。
// 同时被黑白名单引用时白名单先判，实际是放行——这个结论不能报反。
func TestLookupGroupRefEffect(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.IPGroup{BaseOrm: newLookupBase("g1"), GroupName: "办公出口", GroupCode: "office"})
	db.Create(&model.IPGroupItem{BaseOrm: newLookupBase("gi1"), GroupCode: "office", Ip: "192.168.1.0/24"})
	db.Create(&model.IPBlockList{BaseOrm: newLookupBase("b1"), HostCode: "hostA", IpType: model.IPEntryTypeGroup, GroupCode: "office"})

	resp, _ := WafIPLookupServiceApp.Lookup("192.168.1.9", nil)
	if len(resp.Hits) != 1 {
		t.Fatalf("期望只命中IP组1条(引用行本身无IP不该重复计)，实际 %+v", resp.Hits)
	}
	if resp.Hits[0].Source != srcIPGroup || resp.Hits[0].Effect != "block" {
		t.Fatalf("被黑名单引用的组应判 block，实际 %+v", resp.Hits[0])
	}

	// 再加一个白名单引用，效果应翻成放行
	db.Create(&model.IPAllowList{BaseOrm: newLookupBase("a1"), HostCode: "hostA", IpType: model.IPEntryTypeGroup, GroupCode: "office"})
	resp2, _ := WafIPLookupServiceApp.Lookup("192.168.1.9", nil)
	if resp2.Hits[0].Effect != "allow" {
		t.Fatalf("黑白名单同时引用同一组时白名单优先，应为 allow，实际 %q", resp2.Hits[0].Effect)
	}
}

// TestLookupFirewallExpired 已过期但没清理的封禁记录还躺在表里，
// 不能报成「生效中」，否则用户会照着一条早失效的记录排查半天
func TestLookupFirewallExpired(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.FirewallIPBlock{
		BaseOrm: newLookupBase("f1"), IP: "8.8.8.8", Status: "active",
		BlockType: "manual", ExpireTime: 1000, // 1970 年，早过期
	})
	db.Create(&model.FirewallIPBlock{
		BaseOrm: newLookupBase("f2"), IP: "9.9.9.9", Status: "active",
		BlockType: "auto", ExpireTime: 0, // 永久
	})

	if resp, _ := WafIPLookupServiceApp.Lookup("8.8.8.8", nil); len(resp.Hits) != 0 {
		t.Fatalf("过期封禁不该算命中，实际 %+v", resp.Hits)
	}
	resp, _ := WafIPLookupServiceApp.Lookup("9.9.9.9", nil)
	if len(resp.Hits) != 1 || resp.Hits[0].Source != srcFirewall {
		t.Fatalf("永久封禁应命中，实际 %+v", resp.Hits)
	}
}

// TestLookupNoHit 干净的库里查任何IP都应返回空命中而不是报错，
// 前端靠这个区分「没查到」和「查询失败」
func TestLookupNoHit(t *testing.T) {
	setupIPLookupTestDB(t)
	resp, err := WafIPLookupServiceApp.Lookup("203.0.113.7", nil)
	if err != nil {
		t.Fatalf("空库查询不该报错: %v", err)
	}
	if len(resp.Hits) != 0 {
		t.Fatalf("期望0条命中，实际 %+v", resp.Hits)
	}
	if resp.Hits == nil {
		t.Fatal("hits 必须是空数组而不是 null，否则前端 .length 会炸")
	}
}

// TestLookupInvalidIP 非法输入要给明确错误，不能当成空结果
func TestLookupInvalidIP(t *testing.T) {
	setupIPLookupTestDB(t)
	if _, err := WafIPLookupServiceApp.Lookup("not-an-ip", nil); err == nil {
		t.Fatal("非法IP应返回错误")
	}
	if _, err := WafIPLookupServiceApp.Lookup("  ", nil); err == nil {
		t.Fatal("空输入应返回错误")
	}
}

// TestLookupSystemLayerFlag 防火墙封禁是内核层丢包，必须标 SystemLayer；
// 前端靠它提示「加白名单也不会通」。漏标就会让用户加完白以为好了，实际还是连不上。
func TestLookupSystemLayerFlag(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.FirewallIPBlock{
		BaseOrm: newLookupBase("f1"), IP: "5.5.5.5", Status: "active", BlockType: "manual",
	})
	resp, _ := WafIPLookupServiceApp.Lookup("5.5.5.5", nil)
	if len(resp.Hits) != 1 || !resp.Hits[0].SystemLayer {
		t.Fatalf("防火墙封禁应标记为系统层，实际 %+v", resp.Hits)
	}

	// WAF 层的黑名单不该被误标成系统层，否则每次加白都会弹一个无关的警告
	db.Create(&model.IPBlockList{BaseOrm: newLookupBase("b1"), HostCode: "", Ip: "6.6.6.6"})
	resp2, _ := WafIPLookupServiceApp.Lookup("6.6.6.6", nil)
	if len(resp2.Hits) != 1 || resp2.Hits[0].SystemLayer {
		t.Fatalf("IP黑名单只在WAF层，不该标系统层，实际 %+v", resp2.Hits)
	}
}

// TestLandsOnSystem 落地层判定：只有 system/both 才算落到内核
func TestLandsOnSystem(t *testing.T) {
	for v, want := range map[string]bool{"system": true, "both": true, "waf": false, "": false} {
		if landsOnSystem(v) != want {
			t.Fatalf("landsOnSystem(%q) 应为 %v", v, want)
		}
	}
}

// TestLookupAcceptsCIDR 从「查看IP」列表点进来时传的是网段，
// 不能直接判非法——取代表IP查，并如实说明查的是哪个
func TestLookupAcceptsCIDR(t *testing.T) {
	db := setupIPLookupTestDB(t)
	db.Create(&model.IPBlockList{BaseOrm: newLookupBase("b1"), HostCode: "", Ip: "1.2.3.0/24"})

	resp, err := WafIPLookupServiceApp.Lookup("1.2.3.0/24", nil)
	if err != nil {
		t.Fatalf("网段输入不该报错: %v", err)
	}
	if resp.IP != "1.2.3.0" {
		t.Fatalf("应归一到网络地址，实际 %q", resp.IP)
	}
	if resp.QueryNote == "" {
		t.Fatal("归一化了就必须告诉用户查的是哪个IP")
	}
	if len(resp.Hits) != 1 {
		t.Fatalf("应命中该网段本身，实际 %+v", resp.Hits)
	}

	// 单个IP不该产生说明文案，否则每次查询都挂一条噪音
	if r2, _ := WafIPLookupServiceApp.Lookup("1.2.3.9", nil); r2.QueryNote != "" {
		t.Fatalf("单IP不该有归一说明，实际 %q", r2.QueryNote)
	}
	// 区间取起始
	if r3, _ := WafIPLookupServiceApp.Lookup("1.2.3.5-1.2.3.9", nil); r3.IP != "1.2.3.5" {
		t.Fatalf("区间应取起始，实际 %q", r3.IP)
	}
}
