package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafenginecore/ipset"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupIPGroupTestDB 建一个临时 sqlite 库，接管全局 DB 并在用例结束后还原。
func setupIPGroupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "ipgroup_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.IPGroup{}, &model.IPGroupItem{}, &model.IPBlockList{}, &model.IPAllowList{}, &model.Hosts{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-ipgroup"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		ipset.SetGroupSnapshot(nil)
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func mustAddGroup(t *testing.T, name string) model.IPGroup {
	t.Helper()
	g, err := WafIPGroupServiceApp.AddApi(request.WafIPGroupAddReq{GroupName: name})
	if err != nil {
		t.Fatalf("新建IP组失败: %v", err)
	}
	return g
}

// mustCreateBlockRef / mustCreateAllowRef 造一条「引用IP组」的名单行。
// 必须显式给主键：BaseOrm.Id 是字符串主键，留空会让多行撞同一个空 PK，
// 第二行起静默插入失败，用例就会在错误的前提上做断言。
func mustCreateBlockRef(t *testing.T, db *gorm.DB, id, hostCode, groupCode string) {
	t.Helper()
	row := &model.IPBlockList{
		BaseOrm:   baseorm.BaseOrm{Id: id},
		HostCode:  hostCode,
		IpType:    model.IPEntryTypeGroup,
		GroupCode: groupCode,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("造黑名单引用行失败: %v", err)
	}
}

func mustCreateAllowRef(t *testing.T, db *gorm.DB, id, hostCode, groupCode string) {
	t.Helper()
	row := &model.IPAllowList{
		BaseOrm:   baseorm.BaseOrm{Id: id},
		HostCode:  hostCode,
		IpType:    model.IPEntryTypeGroup,
		GroupCode: groupCode,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("造白名单引用行失败: %v", err)
	}
}

func TestIPGroup_AddAndRebuildMatcher(t *testing.T) {
	setupIPGroupTestDB(t)
	g := mustAddGroup(t, "办公室出口")

	if err := WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: "10.10.*.*"}); err != nil {
		t.Fatalf("添加组内条目失败: %v", err)
	}
	WafIPGroupServiceApp.RebuildGroupMatcher(g.GroupCode)

	if !ipset.GetGroupMatcher(g.GroupCode).ContainsStr("10.10.1.1") {
		t.Error("按组短码应当命中")
	}
	if !ipset.LookupGroupMatcher("办公室出口").ContainsStr("10.10.1.1") {
		t.Error("按组名称应当命中")
	}
	if ipset.GetGroupMatcher(g.GroupCode).ContainsStr("10.11.1.1") {
		t.Error("组外地址不应命中")
	}
}

// 组名在租户内唯一；组短码由后端自动生成且互不相同
func TestIPGroup_DuplicateNameRejected(t *testing.T) {
	setupIPGroupTestDB(t)
	g1 := mustAddGroup(t, "重名组")
	if _, err := WafIPGroupServiceApp.AddApi(request.WafIPGroupAddReq{GroupName: "重名组"}); err == nil {
		t.Error("重复组名应当被拒绝")
	}
	g2 := mustAddGroup(t, "另一个组")
	if g1.GroupCode == "" || g2.GroupCode == "" {
		t.Error("组短码应当由后端自动生成，不能为空")
	}
	if g1.GroupCode == g2.GroupCode {
		t.Error("自动生成的组短码不能重复")
	}
}

// 组内条目的格式校验：合法写法全通过，非法写法与全通配被拒
func TestIPGroupItem_Validation(t *testing.T) {
	setupIPGroupTestDB(t)
	g := mustAddGroup(t, "校验组")

	valid := []string{"1.2.3.4", "10.0.0.0/8", "10.10.*.*", "10.*.1.*",
		"1.2.3.4-1.2.3.99", "2001:db8::1", "2001:db8:*:*:*:*:*:*"}
	for _, ip := range valid {
		if err := WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: ip}); err != nil {
			t.Errorf("合法写法 %q 被拒: %v", ip, err)
		}
	}

	invalid := []string{"", "10.1*.0.0", "2001:db8::*", "10.*.*.*/8", "1.2.3.99-1.2.3.4",
		"*.*.*.*" /* 全通配：语法合法但风险过高，单独拦下 */}
	for _, ip := range invalid {
		if err := WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: ip}); err == nil {
			t.Errorf("非法写法 %q 应当被拒", ip)
		}
	}

	// 组内重复
	if err := WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: "1.2.3.4"}); err == nil {
		t.Error("组内重复IP应当被拒")
	}
	// 组不存在
	if err := WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: "不存在", Ip: "1.2.3.4"}); err == nil {
		t.Error("向不存在的组添加条目应当被拒")
	}
}

func TestIPGroupItem_BatchAdd_PartialInvalid(t *testing.T) {
	setupIPGroupTestDB(t)
	g := mustAddGroup(t, "批量组")

	content := `# 这是注释行

1.2.3.4
10.10.*.*
10.1*.0.0
1.2.3.4-1.2.3.99
垃圾内容
1.2.3.4
`
	result, err := WafIPGroupItemServiceApp.BatchAddApi(request.WafIPGroupItemBatchAddReq{
		GroupCode: g.GroupCode, Content: content,
	})
	if err != nil {
		t.Fatalf("批量添加失败: %v", err)
	}
	// 有效行 6 条（注释与空行不计）：3 成功 + 2 非法 + 1 重复
	if result.Total != 6 {
		t.Errorf("Total = %d, want 6（注释行与空行不计入）", result.Total)
	}
	if result.Success != 3 {
		t.Errorf("Success = %d, want 3", result.Success)
	}
	if result.Fail != 2 {
		t.Errorf("Fail = %d, want 2", result.Fail)
	}
	if result.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1（同批次内的重复行）", result.Skipped)
	}
	if len(result.FailLines) != 2 {
		t.Errorf("FailLines 应返回 2 条明细，实际 %d", len(result.FailLines))
	}

	WafIPGroupServiceApp.RebuildGroupMatcher(g.GroupCode)
	m := ipset.GetGroupMatcher(g.GroupCode)
	if !m.ContainsStr("10.10.9.9") || !m.ContainsStr("1.2.3.50") {
		t.Error("批量添加的通配符与区间应当生效")
	}
}

// 删除被引用的组：不带 force 必须拒绝且一行数据都不能少
func TestIPGroup_DeleteWithRefs_RejectedWithoutForce(t *testing.T) {
	db := setupIPGroupTestDB(t)
	g := mustAddGroup(t, "被引用组")
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: "1.2.3.4"})

	// 站点 A 黑名单、站点 B 白名单各引用一次
	mustCreateBlockRef(t, db, "b1", "hostA", g.GroupCode)
	mustCreateAllowRef(t, db, "a1", "hostB", g.GroupCode)

	refs := WafIPGroupServiceApp.GetRefsApi(g.GroupCode)
	if refs.BlockCount != 1 || refs.AllowCount != 1 {
		t.Fatalf("引用统计错误: block=%d allow=%d", refs.BlockCount, refs.AllowCount)
	}
	if len(refs.Hosts) != 2 {
		t.Errorf("应涉及 2 个站点，实际 %d", len(refs.Hosts))
	}

	if _, err := WafIPGroupServiceApp.DelApi(request.WafIPGroupDelReq{Id: g.Id}); err == nil {
		t.Fatal("被引用的组在不带 force 时应当拒绝删除")
	}

	// 一行都不能少
	var groupCnt, itemCnt, blockCnt, allowCnt int64
	db.Model(&model.IPGroup{}).Count(&groupCnt)
	db.Model(&model.IPGroupItem{}).Count(&itemCnt)
	db.Model(&model.IPBlockList{}).Count(&blockCnt)
	db.Model(&model.IPAllowList{}).Count(&allowCnt)
	if groupCnt != 1 || itemCnt != 1 || blockCnt != 1 || allowCnt != 1 {
		t.Errorf("拒绝删除后数据不应有任何变化: group=%d item=%d block=%d allow=%d",
			groupCnt, itemCnt, blockCnt, allowCnt)
	}
}

// force=1 级联删除：组、条目、引用行全清，且返回受影响的站点用于去脏
func TestIPGroup_DeleteWithRefs_ForceCascades(t *testing.T) {
	db := setupIPGroupTestDB(t)
	g := mustAddGroup(t, "强删组")
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: "1.2.3.4"})
	WafIPGroupServiceApp.RebuildGroupMatcher(g.GroupCode)

	mustCreateBlockRef(t, db, "b1", "hostA", g.GroupCode)
	mustCreateAllowRef(t, db, "a1", "hostB", g.GroupCode)
	// 另一条无关的单条黑名单行，不能被误删
	if err := db.Create(&model.IPBlockList{BaseOrm: baseorm.BaseOrm{Id: "b-plain"}, HostCode: "hostA", Ip: "9.9.9.9"}).Error; err != nil {
		t.Fatalf("造无关黑名单行失败: %v", err)
	}

	affected, err := WafIPGroupServiceApp.DelApi(request.WafIPGroupDelReq{Id: g.Id, Force: 1})
	if err != nil {
		t.Fatalf("force 删除失败: %v", err)
	}
	if len(affected) != 2 {
		t.Errorf("应返回 2 个受影响站点，实际 %v", affected)
	}

	var groupCnt, itemCnt, allowCnt, blockCnt int64
	db.Model(&model.IPGroup{}).Count(&groupCnt)
	db.Model(&model.IPGroupItem{}).Count(&itemCnt)
	db.Model(&model.IPAllowList{}).Count(&allowCnt)
	db.Model(&model.IPBlockList{}).Count(&blockCnt)
	if groupCnt != 0 || itemCnt != 0 || allowCnt != 0 {
		t.Errorf("force 删除后组/条目/引用行应全清: group=%d item=%d allow=%d", groupCnt, itemCnt, allowCnt)
	}
	if blockCnt != 1 {
		t.Errorf("无关的单条黑名单行不应被误删，剩余 %d 条", blockCnt)
	}
	// 快照里也要摘掉
	if ipset.GetGroupMatcher(g.GroupCode) != nil {
		t.Error("组删除后应从全局快照中摘除")
	}
}

// 改名后：新名字可查、旧名字失效、短码不变
func TestIPGroup_RenameRefreshesNameIndex(t *testing.T) {
	setupIPGroupTestDB(t)
	g := mustAddGroup(t, "旧名字")
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g.GroupCode, Ip: "1.2.3.4"})
	WafIPGroupServiceApp.RebuildGroupMatcher(g.GroupCode)

	if _, err := WafIPGroupServiceApp.ModifyApi(request.WafIPGroupEditReq{Id: g.Id, GroupName: "新名字"}); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	WafIPGroupServiceApp.RebuildGroupMatcher(g.GroupCode)

	if ipset.LookupGroupMatcher("旧名字") != nil {
		t.Error("改名后旧名字不应再能查到（规则里写旧名会命中一个已不存在的组）")
	}
	if ipset.LookupGroupMatcher("新名字") == nil {
		t.Error("改名后新名字应当可查")
	}
	if ipset.GetGroupMatcher(g.GroupCode) == nil {
		t.Error("改名不应影响短码索引")
	}
}

func TestIPGroup_RebuildAllGroupMatchers(t *testing.T) {
	setupIPGroupTestDB(t)
	g1 := mustAddGroup(t, "组一")
	g2 := mustAddGroup(t, "组二")
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g1.GroupCode, Ip: "10.0.0.0/8"})
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g2.GroupCode, Ip: "172.16.0.0/12"})

	ipset.SetGroupSnapshot(nil) // 模拟进程重启
	WafIPGroupServiceApp.RebuildAllGroupMatchers()

	groups, entries := ipset.GroupStats()
	if groups != 2 || entries != 2 {
		t.Errorf("GroupStats = (%d,%d), want (2,2)", groups, entries)
	}
	if !ipset.LookupGroupMatcher("组一").ContainsStr("10.1.2.3") {
		t.Error("启动重建后组一应当可用")
	}
	if !ipset.LookupGroupMatcher("组二").ContainsStr("172.16.1.1") {
		t.Error("启动重建后组二应当可用")
	}
}

func TestIPGroup_GetHostCodesByGroup(t *testing.T) {
	db := setupIPGroupTestDB(t)
	g := mustAddGroup(t, "统计组")
	mustCreateBlockRef(t, db, "b1", "hostA", g.GroupCode)
	mustCreateBlockRef(t, db, "b2", "hostA", g.GroupCode) // 同站点引用两次，应去重
	mustCreateAllowRef(t, db, "a1", "hostB", g.GroupCode)

	codes := WafIPGroupServiceApp.GetHostCodesByGroup(g.GroupCode)
	if len(codes) != 2 {
		t.Errorf("应返回 2 个去重后的站点，实际 %v", codes)
	}
}

// 列表接口的条目数聚合不能 N+1，也不能算错
func TestIPGroup_ListFillsItemCount(t *testing.T) {
	setupIPGroupTestDB(t)
	g1 := mustAddGroup(t, "有条目的组")
	mustAddGroup(t, "空组")
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g1.GroupCode, Ip: "1.2.3.4"})
	_ = WafIPGroupItemServiceApp.AddApi(request.WafIPGroupItemAddReq{GroupCode: g1.GroupCode, Ip: "5.6.7.8"})

	options := WafIPGroupServiceApp.GetOptionsApi()
	if len(options) != 2 {
		t.Fatalf("应返回 2 个组，实际 %d", len(options))
	}
	for _, o := range options {
		want := 0
		if o.GroupCode == g1.GroupCode {
			want = 2
		}
		if o.ItemCount != want {
			t.Errorf("组 %s 的 ItemCount = %d, want %d", o.GroupName, o.ItemCount, want)
		}
	}
}
