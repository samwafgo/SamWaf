package waf_service

import (
	"path/filepath"
	"testing"
	"time"

	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	commonreq "SamWaf/model/common/request"
	"SamWaf/model/request"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupHostGroupTestDB 建一个临时 sqlite 库，接管全局 DB 并在用例结束后还原。
func setupHostGroupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "hostgroup_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.HostGroup{}, &model.Hosts{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-hostgroup"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func mustAddHostGroup(t *testing.T, name string) model.HostGroup {
	t.Helper()
	g, err := WafHostGroupServiceApp.AddApi(request.WafHostGroupAddReq{GroupName: name})
	if err != nil {
		t.Fatalf("新建分组失败: %v", err)
	}
	return g
}

// mustCreateHost 造一条网站记录。groupCode 为空即未分组；global=1 表示全局网站。
func mustCreateHost(t *testing.T, host, groupCode string, globalHost int) model.Hosts {
	t.Helper()
	bean := model.Hosts{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Code:        uuid.GenUUID(),
		Host:        host,
		Port:        80,
		GLOBAL_HOST: globalHost,
		GroupCode:   groupCode,
	}
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		t.Fatalf("造网站记录失败: %v", err)
	}
	return bean
}

// TestHostGroupDelKeepsHosts 删除分组只清引用，网站本身必须留着。
func TestHostGroupDelKeepsHosts(t *testing.T) {
	setupHostGroupTestDB(t)
	g := mustAddHostGroup(t, "生产环境")
	mustCreateHost(t, "a.com", g.GroupCode, 0)
	mustCreateHost(t, "b.com", g.GroupCode, 0)

	affected, err := WafHostGroupServiceApp.DelApi(request.WafHostGroupDelReq{Id: g.Id})
	if err != nil {
		t.Fatalf("删除分组失败: %v", err)
	}
	if affected != 2 {
		t.Fatalf("期望 2 个网站被移出分组，实际 %d", affected)
	}
	var hostCnt int64
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Count(&hostCnt)
	if hostCnt != 2 {
		t.Fatalf("删组不应删网站，期望 2 条网站记录，实际 %d", hostCnt)
	}
	var groupCnt int64
	global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).Count(&groupCnt)
	if groupCnt != 0 {
		t.Fatalf("分组应已删除，实际还剩 %d", groupCnt)
	}
}

// TestHostGroupNoneFilterCoversNullAndEmpty 「未分组」筛选必须同时命中 NULL 与空串。
// 存量行落的是哪一种取决于数据库，只判一种会漏掉一半站点。
func TestHostGroupNoneFilterCoversNullAndEmpty(t *testing.T) {
	db := setupHostGroupTestDB(t)
	g := mustAddHostGroup(t, "生产环境")
	mustCreateHost(t, "grouped.com", g.GroupCode, 0)
	mustCreateHost(t, "empty.com", "", 0)
	nullHost := mustCreateHost(t, "null.com", "", 0)
	// 手工把一条改成 NULL，模拟 AddColumn 之后未回填的存量行
	if err := db.Exec("UPDATE hosts SET group_code = NULL WHERE id = ?", nullHost.Id).Error; err != nil {
		t.Fatalf("构造 NULL 行失败: %v", err)
	}

	list, total, err := WafHostServiceApp.GetListApi(request.WafHostSearchReq{
		GroupCode: model.HostGroupNone,
		PageInfo:  commonreq.PageInfo{PageIndex: 1, PageSize: 20},
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 2 || len(list) != 2 {
		t.Fatalf("未分组筛选应命中 2 条(空串+NULL)，实际 total=%d len=%d", total, len(list))
	}

	// 指定分组时走精确匹配
	list, total, err = WafHostServiceApp.GetListApi(request.WafHostSearchReq{
		GroupCode: g.GroupCode,
		PageInfo:  commonreq.PageInfo{PageIndex: 1, PageSize: 20},
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].Host != "grouped.com" {
		t.Fatalf("分组筛选结果不符: total=%d len=%d", total, len(list))
	}
}

// TestHostGroupGroupCodeIsExactMatch 短码走精确匹配，不能像其它过滤字段那样 like 串组。
func TestHostGroupGroupCodeIsExactMatch(t *testing.T) {
	setupHostGroupTestDB(t)
	mustCreateHost(t, "a.com", "abc", 0)
	mustCreateHost(t, "b.com", "abcdef", 0)

	_, total, err := WafHostServiceApp.GetListApi(request.WafHostSearchReq{
		GroupCode: "abc",
		PageInfo:  commonreq.PageInfo{PageIndex: 1, PageSize: 20},
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 {
		t.Fatalf("短码应精确匹配，期望 1 条，实际 %d（走 like 会把 abcdef 也带出来）", total)
	}
}

// TestHostGroupAssignSkipsGlobalHost 全局网站不参与分组，即使被前端全选带上来也要剔除。
func TestHostGroupAssignSkipsGlobalHost(t *testing.T) {
	setupHostGroupTestDB(t)
	g := mustAddHostGroup(t, "生产环境")
	normal := mustCreateHost(t, "a.com", "", 0)
	globalHost := mustCreateHost(t, "全局网站", "", 1)

	affected, err := WafHostGroupServiceApp.AssignApi(request.WafHostGroupAssignReq{
		HostCodes: []string{normal.Code, globalHost.Code},
		GroupCode: g.GroupCode,
	})
	if err != nil {
		t.Fatalf("批量移动失败: %v", err)
	}
	if affected != 1 {
		t.Fatalf("全局网站应被剔除，期望生效 1 条，实际 %d", affected)
	}
	var reloaded model.Hosts
	global.GWAF_LOCAL_DB.Where("code = ?", globalHost.Code).First(&reloaded)
	if reloaded.GroupCode != "" {
		t.Fatalf("全局网站不应被分组，实际 group_code=%s", reloaded.GroupCode)
	}
}

// TestHostGroupAssignRejectsMissingGroup 目标分组已被删掉时必须拒绝，而不是写入悬空短码。
func TestHostGroupAssignRejectsMissingGroup(t *testing.T) {
	setupHostGroupTestDB(t)
	h := mustCreateHost(t, "a.com", "", 0)
	if _, err := WafHostGroupServiceApp.AssignApi(request.WafHostGroupAssignReq{
		HostCodes: []string{h.Code},
		GroupCode: "not-exist",
	}); err == nil {
		t.Fatal("目标分组不存在时应报错")
	}
	// 移出分组（空 group_code）始终允许
	if _, err := WafHostGroupServiceApp.AssignApi(request.WafHostGroupAssignReq{
		HostCodes: []string{h.Code},
		GroupCode: "",
	}); err != nil {
		t.Fatalf("移出分组不应报错: %v", err)
	}
}

// TestHostGroupDuplicateNameRejected 同名分组要拒绝。
func TestHostGroupDuplicateNameRejected(t *testing.T) {
	setupHostGroupTestDB(t)
	mustAddHostGroup(t, "生产环境")
	if _, err := WafHostGroupServiceApp.AddApi(request.WafHostGroupAddReq{GroupName: " 生产环境 "}); err == nil {
		t.Fatal("同名分组(trim 后相同)应被拒绝")
	}
}

// TestHostGroupColorWhitelist 颜色只收预设枚举——它是唯一会被渲染进管理端 DOM 属性的分组字段。
func TestHostGroupColorWhitelist(t *testing.T) {
	setupHostGroupTestDB(t)
	if _, err := WafHostGroupServiceApp.AddApi(request.WafHostGroupAddReq{
		GroupName: "注入组", Color: "red;background:url(javascript:1)",
	}); err == nil {
		t.Fatal("非预设颜色应被拒绝")
	}
	g, err := WafHostGroupServiceApp.AddApi(request.WafHostGroupAddReq{GroupName: "默认色组"})
	if err != nil {
		t.Fatalf("新建分组失败: %v", err)
	}
	if g.Color != model.HostGroupColors[0] {
		t.Fatalf("未传颜色时应给默认色，实际 %s", g.Color)
	}
}

// TestHostGroupOptionsCounts 左栏计数：各组网站数 + 未分组 + 全部，均不含全局网站。
func TestHostGroupOptionsCounts(t *testing.T) {
	setupHostGroupTestDB(t)
	g1 := mustAddHostGroup(t, "生产环境")
	g2 := mustAddHostGroup(t, "测试环境")
	mustCreateHost(t, "a.com", g1.GroupCode, 0)
	mustCreateHost(t, "b.com", g1.GroupCode, 0)
	mustCreateHost(t, "c.com", g2.GroupCode, 0)
	mustCreateHost(t, "d.com", "", 0)
	mustCreateHost(t, "全局网站", "", 1)

	opts := WafHostGroupServiceApp.GetOptionsApi()
	if opts.AllCount != 4 {
		t.Fatalf("全部计数应排除全局网站，期望 4，实际 %d", opts.AllCount)
	}
	if opts.NoneCount != 1 {
		t.Fatalf("未分组计数应排除全局网站，期望 1，实际 %d", opts.NoneCount)
	}
	if len(opts.List) != 2 {
		t.Fatalf("期望 2 个分组，实际 %d", len(opts.List))
	}
	got := map[string]int{}
	for _, g := range opts.List {
		got[g.GroupName] = g.HostCount
	}
	if got["生产环境"] != 2 || got["测试环境"] != 1 {
		t.Fatalf("分组计数不符: %v", got)
	}
	// 新组按 sort_no 递增排在后面
	if opts.List[0].GroupName != "生产环境" {
		t.Fatalf("分组应按 sort_no 排序，实际首个是 %s", opts.List[0].GroupName)
	}
}

// TestHostGroupSort 排序按提交的 id 顺序重写 sort_no。
func TestHostGroupSort(t *testing.T) {
	setupHostGroupTestDB(t)
	g1 := mustAddHostGroup(t, "A")
	g2 := mustAddHostGroup(t, "B")
	g3 := mustAddHostGroup(t, "C")

	if err := WafHostGroupServiceApp.SortApi(request.WafHostGroupSortReq{
		Ids: []string{g3.Id, g1.Id, g2.Id},
	}); err != nil {
		t.Fatalf("排序失败: %v", err)
	}
	opts := WafHostGroupServiceApp.GetOptionsApi()
	want := []string{"C", "A", "B"}
	for i, w := range want {
		if opts.List[i].GroupName != w {
			t.Fatalf("排序结果不符，位置 %d 期望 %s，实际 %s", i, w, opts.List[i].GroupName)
		}
	}
}
