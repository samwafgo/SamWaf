//go:build crossdb

// ip_tags 相关查询的三库回归：验证「不算风险的标签」排除逻辑在 SQLite/MySQL/PostgreSQL 上
// 都能执行且结果正确。由 TestCrossEngine 每引擎调一次。
//
// 重点防的是参数顺序：GetAttackIpListApi 里 IN 列表在 SELECT / HAVING 各出现一次，
// 占位符与参数一旦错位，SQL 不报错但 pass_num/deny_num 会静默算错。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/request"
	req "SamWaf/model/request"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func seedIPTag(t *testing.T, db *gorm.DB, ip, tag string, cnt int64) {
	t.Helper()
	must(t, db.Create(&model.IPTag{
		BaseOrm: newBase(uuid.GenUUID()),
		IP:      ip,
		IPTag:   tag,
		Cnt:     cnt,
	}).Error)
}

func findAllTag(list []model.AllIPTag, value string) (model.AllIPTag, bool) {
	for _, item := range list {
		if item.Value == value {
			return item, true
		}
	}
	return model.AllIPTag{}, false
}

func findAttackIP(list []model.AttackIPTag, ip string) (model.AttackIPTag, bool) {
	for _, item := range list {
		if item.IP == ip {
			return item, true
		}
	}
	return model.AttackIPTag{}, false
}

func runIPTagCases(t *testing.T, coredb *gorm.DB) {
	svc := WafLogService{}
	oldExclude := global.GCONFIG_ATTACK_TAG_EXCLUDE
	defer func() { global.GCONFIG_ATTACK_TAG_EXCLUDE = oldExclude }()

	// 干净起步：本用例独占 ip_tags
	must(t, coredb.Exec("DELETE FROM ip_tags").Error)

	// 1.1.1.1 真攻击；2.2.2.2 只做过 ACME 校验；3.3.3.3 只有历史遗留的静态访问标签
	seedIPTag(t, coredb, "1.1.1.1", "正常", 10)
	seedIPTag(t, coredb, "1.1.1.1", "SQL注入", 3)
	seedIPTag(t, coredb, "2.2.2.2", "正常", 5)
	seedIPTag(t, coredb, "2.2.2.2", "ACME证书校验", 7)
	seedIPTag(t, coredb, "3.3.3.3", "静态文件访问成功", 100)
	seedIPTag(t, coredb, "4.4.4.4", "XSS跨站注入", 2)

	global.GCONFIG_ATTACK_TAG_EXCLUDE = "ACME证书校验,静态文件访问成功"

	// —— 规则筛选列表：只剩真攻击标签，且 count 单独返回 ——
	t.Run("tag_list_excludes_benign", func(t *testing.T) {
		list, err := svc.GetAllAttackIPTagListApi(false)
		fatalIf(t, err)
		if len(list) != 2 {
			t.Fatalf("规则标签期望 2 条(SQL注入/XSS跨站注入)，实际 %d 条: %+v", len(list), list)
		}
		for _, bad := range []string{"正常", "ACME证书校验", "静态文件访问成功"} {
			if _, ok := findAllTag(list, bad); ok {
				t.Fatalf("标签 %s 不该出现在规则筛选列表里: %+v", bad, list)
			}
		}
		sqli, ok := findAllTag(list, "SQL注入")
		if !ok {
			t.Fatalf("规则筛选列表里找不到 SQL注入: %+v", list)
		}
		eq64(t, "SQL注入 的 count", sqli.Count, 3)
		if !strings.Contains(sqli.Label, "3") {
			t.Fatalf("label 仍应带计数(兼容老前端)，实际 %q", sqli.Label)
		}
		// 量大的排前面
		if list[0].Value != "SQL注入" {
			t.Fatalf("应按计数倒序，首项期望 SQL注入，实际 %s", list[0].Value)
		}
	})

	// —— IP 聚合列表：被排除的标签算放行，只有这些标签的 IP 整条不出现 ——
	t.Run("ip_list_benign_counts_as_pass", func(t *testing.T) {
		list, total, err := svc.GetAttackIpListApi(req.WafAttackIpTagSearch{PageInfo: request.PageInfo{PageIndex: 1, PageSize: 10}})
		fatalIf(t, err)
		eq64(t, "风险 IP 总数", total, 2)
		if len(list) != 2 {
			t.Fatalf("风险 IP 期望 2 条，实际 %d 条: %+v", len(list), list)
		}
		if _, ok := findAttackIP(list, "2.2.2.2"); ok {
			t.Fatalf("只做过 ACME 校验的 IP 不该出现在风险日志里: %+v", list)
		}
		if _, ok := findAttackIP(list, "3.3.3.3"); ok {
			t.Fatalf("只有静态访问标签的 IP 不该出现在风险日志里: %+v", list)
		}
		one, ok := findAttackIP(list, "1.1.1.1")
		if !ok {
			t.Fatalf("风险 IP 列表里找不到 1.1.1.1: %+v", list)
		}
		eq64(t, "1.1.1.1 放行数量", one.PassNum, 10)
		eq64(t, "1.1.1.1 阻止数量", one.DenyNum, 3)
		if !strings.Contains(one.IpTotalTag, "SQL注入") || strings.Contains(one.IpTotalTag, "正常") {
			t.Fatalf("触发规则集合应只含攻击标签，实际 %q", one.IpTotalTag)
		}
	})

	// —— 清空排除配置：ACME 立刻回到风险口径（证明配置真的生效，不是写死的） ——
	t.Run("empty_exclude_restores_acme", func(t *testing.T) {
		global.GCONFIG_ATTACK_TAG_EXCLUDE = ""
		defer func() { global.GCONFIG_ATTACK_TAG_EXCLUDE = "ACME证书校验,静态文件访问成功" }()

		tagList, err := svc.GetAllAttackIPTagListApi(false)
		fatalIf(t, err)
		if _, ok := findAllTag(tagList, "ACME证书校验"); !ok {
			t.Fatalf("清空排除后 ACME证书校验 应回到规则列表: %+v", tagList)
		}
		if _, ok := findAllTag(tagList, "正常"); ok {
			t.Fatalf("「正常」永远不该出现在规则列表里: %+v", tagList)
		}

		ipList, total, err := svc.GetAttackIpListApi(req.WafAttackIpTagSearch{PageInfo: request.PageInfo{PageIndex: 1, PageSize: 10}})
		fatalIf(t, err)
		eq64(t, "清空排除后的风险 IP 总数", total, 4)
		acmeIP, ok := findAttackIP(ipList, "2.2.2.2")
		if !ok {
			t.Fatalf("清空排除后 2.2.2.2 应出现: %+v", ipList)
		}
		eq64(t, "2.2.2.2 阻止数量", acmeIP.DenyNum, 7)
		eq64(t, "2.2.2.2 放行数量", acmeIP.PassNum, 5)
	})

	// —— withBenign：批量删除弹窗要能看到被排除的标签，否则历史数据没法清 ——
	t.Run("with_benign_lists_excluded_tags", func(t *testing.T) {
		list, err := svc.GetAllAttackIPTagListApi(true)
		fatalIf(t, err)
		for _, want := range []string{"ACME证书校验", "静态文件访问成功", "SQL注入"} {
			if _, ok := findAllTag(list, want); !ok {
				t.Fatalf("withBenign 应包含 %s: %+v", want, list)
			}
		}
		if _, ok := findAllTag(list, "正常"); ok {
			t.Fatalf("「正常」不给删也不该列出来: %+v", list)
		}
	})

	// —— 按规则筛选仍然正常 ——
	t.Run("filter_by_rule", func(t *testing.T) {
		list, total, err := svc.GetAttackIpListApi(req.WafAttackIpTagSearch{Rule: "SQL注入", PageInfo: request.PageInfo{PageIndex: 1, PageSize: 10}})
		fatalIf(t, err)
		eq64(t, "按 SQL注入 筛选的总数", total, 1)
		if len(list) != 1 || list[0].IP != "1.1.1.1" {
			t.Fatalf("按规则筛选结果不对: %+v", list)
		}
		eq64(t, "筛选后 1.1.1.1 的阻止数量", list[0].DenyNum, 3)
	})

	must(t, coredb.Exec("DELETE FROM ip_tags").Error)
}
