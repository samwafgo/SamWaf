package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"fmt"
	"strings"
	"time"
)

// benignTags 返回「不算风险」的标签清单：固定的"正常" + 用户配置的 attack_tag_exclude。
// 这些标签既不进规则筛选列表，也算放行而不是阻止——例如 ACME 证书校验是正常业务流量，
// 不排除的话「只做过证书校验」的 IP 会带着阻止数量>0 出现在风险日志里。
func benignTags() []string {
	tags := []string{"正常"}
	seen := map[string]bool{"正常": true}
	for _, t := range strings.Split(global.GCONFIG_ATTACK_TAG_EXCLUDE, ",") {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
	}
	return tags
}

// benignPlaceholders 生成 IN 占位符 ?,?,? —— 标签值来自用户配置，必须参数绑定不能拼 SQL
func benignPlaceholders(n int) string {
	if n <= 0 {
		return "''"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// appendTags SQL 里每出现一次 IN 列表就要补一份参数
func appendTags(params []interface{}, tags []string) []interface{} {
	for _, t := range tags {
		params = append(params, t)
	}
	return params
}

// GetAttackIpListApi 访问IP列表
func (receiver *WafLogService) GetAttackIpListApi(req request.WafAttackIpTagSearch) ([]model.AttackIPTag, int64, error) {
	var results []model.AttackIPTag
	var total int64

	// 基础查询部分（update_time 落库即本地时间，方言层只负责渲染，不做时区换算）
	firstTimeExpr := dialect.Get().FormatLocalTime("MIN(update_time)")
	latestTimeExpr := dialect.Get().FormatLocalTime("MAX(update_time)")
	// 不算风险的标签（正常 + 用户配置的排除项）走参数绑定，SQL 里出现几次就补几份参数
	tags := benignTags()
	ph := benignPlaceholders(len(tags))
	// 聚合去重拼接：SQLite/MySQL 用 GROUP_CONCAT，PostgreSQL 用 string_agg
	ipTotalTagExpr := dialect.Get().GroupConcatDistinct("CASE WHEN ip_tag NOT IN (" + ph + ") THEN ip_tag END")
	query := `
	SELECT
		tenant_id,
		user_code,
		ip,
		SUM(CASE WHEN ip_tag IN (` + ph + `) THEN cnt ELSE 0 END) AS pass_num,
		SUM(CASE WHEN ip_tag NOT IN (` + ph + `) THEN cnt ELSE 0 END) AS deny_num,
		` + firstTimeExpr + ` AS first_time,
		` + latestTimeExpr + ` AS latest_time,
		` + ipTotalTagExpr + ` AS ip_total_tag
	FROM
		ip_tags
	WHERE tenant_id=? and user_code=?`

	// 动态添加过滤条件
	if req.Rule != "" {
		query += " AND ip_tag = ?"
	}
	if req.SrcIp != "" {
		query += " AND ip = ?"
	}

	// 完成查询的其他部分
	query += `
	GROUP BY 
		tenant_id, 
		user_code, 
		ip
	HAVING  
		SUM(CASE WHEN ip_tag NOT IN (` + ph + `) THEN cnt ELSE 0 END) > 0 
	ORDER BY 
		MAX(update_time) DESC
	LIMIT ? OFFSET ?`

	// 构建查询参数：顺序必须与占位符在 SQL 里出现的先后一致
	// pass_num -> deny_num -> ip_total_tag -> tenant/user -> [rule] -> [ip] -> having -> limit/offset
	params := []interface{}{}
	params = appendTags(params, tags) // pass_num
	params = appendTags(params, tags) // deny_num
	params = appendTags(params, tags) // ip_total_tag
	params = append(params, global.GWAF_TENANT_ID, global.GWAF_USER_CODE)

	// 添加 Rule 和 SrcIp 作为参数（如果提供了）
	if req.Rule != "" {
		params = append(params, req.Rule)
	}
	if req.SrcIp != "" {
		params = append(params, req.SrcIp)
	}

	params = appendTags(params, tags) // having

	// 分页参数
	params = append(params, req.PageSize, req.PageSize*(req.PageIndex-1))

	// 执行查询
	ipTagDB := global.GetIPTagDB() // 使用封装方法获取数据库连接
	if err := ipTagDB.Raw(query, params...).Scan(&results).Error; err != nil {
		return nil, 0, err
	}

	// 获取总记录数
	countQuery := `
	SELECT 
		COUNT(*) AS total
	FROM (
		SELECT 
			tenant_id,
			user_code,
			ip
		FROM 
			ip_tags
		WHERE tenant_id=? and user_code=?`

	// 动态添加过滤条件
	if req.Rule != "" {
		countQuery += " AND ip_tag = ?"
	}
	if req.SrcIp != "" {
		countQuery += " AND ip = ?"
	}

	countQuery += `
	GROUP BY 
		tenant_id, 
		user_code, 
		ip
	HAVING  
		SUM(CASE WHEN ip_tag NOT IN (` + ph + `) THEN cnt ELSE 0 END) > 0
	) AS subquery`

	// 获取总记录数参数
	countParams := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE}
	if req.Rule != "" {
		countParams = append(countParams, req.Rule)
	}
	if req.SrcIp != "" {
		countParams = append(countParams, req.SrcIp)
	}
	countParams = appendTags(countParams, tags) // having

	// 执行记录数查询
	if err := ipTagDB.Raw(countQuery, countParams...).Scan(&total).Error; err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

// GetAllAttackIPTagListApi 获取所有攻击Tag
// withBenign=true 时把被排除的标签（ACME证书校验、历史遗留的静态文件访问成功等）也带出来，
// 供批量删除用——否则这些标签一旦被排除，界面上就再也没有入口清理它们残留的数据。
func (receiver *WafLogService) GetAllAttackIPTagListApi(withBenign bool) ([]model.AllIPTag, error) {
	var results []model.AllIPTag

	// 不算风险的标签不进筛选列表；要清理数据时用 withBenign 把它们带出来（"正常"永远不给删）
	tags := benignTags()
	if withBenign {
		tags = []string{"正常"}
	}
	ph := benignPlaceholders(len(tags))
	// 字符串拼接方言差异：SQLite 用 ||，MySQL 用 CONCAT（MySQL 下 || 是逻辑或、双引号是字符串字面量）
	labelExpr := "ip_tag || ' (' || sum(cnt) || ')'"
	if dialect.Get().Name() == "mysql" {
		labelExpr = "CONCAT(ip_tag, ' (', sum(cnt), ')')"
	}
	// 基础查询部分（表名不加引号，sqlite/mysql 通用）
	query := fmt.Sprintf(`
SELECT
    ip_tag as value,
    %s as label,
    sum(cnt) as count
    FROM
    ip_tags
WHERE ip_tag NOT IN (%s) and tenant_id=? and user_code=?
	GROUP BY
    tenant_id,
    ip_tag
order by  sum(cnt) desc
`, labelExpr, ph)

	// 构建查询参数：先 NOT IN 的标签，再租户/用户
	params := []interface{}{}
	params = appendTags(params, tags)
	params = append(params, global.GWAF_TENANT_ID, global.GWAF_USER_CODE)

	// 执行查询
	ipTagDB := global.GetIPTagDB() // 使用封装方法获取数据库连接
	if err := ipTagDB.Raw(query, params...).Scan(&results).Error; err != nil {
		return nil, err
	}

	return results, nil
}

// DeleteTagByNameApi 删除指定标签（支持批量删除大数据量）
func (receiver *WafLogService) DeleteTagByNameApi(tagName string, deleteLogs bool) error {
	ipTagDB := global.GetIPTagDB()

	// 1. 删除 ip_tags 表中的标签数据
	deleteTagQuery := `DELETE FROM ip_tags WHERE tenant_id=? AND user_code=? AND ip_tag=?`
	if err := ipTagDB.Exec(deleteTagQuery, global.GWAF_TENANT_ID, global.GWAF_USER_CODE, tagName).Error; err != nil {
		return fmt.Errorf("删除标签统计数据失败: %v", err)
	}

	// 2. 如果需要删除关联的日志数据
	if deleteLogs {
		// 使用批量删除，避免内存溢出
		// 每次删除一批数据，直到全部删除完成
		batchSize := 1000 // 每批删除1000条

		for {
			// 分批删除日志。web_logs 无主键，只能走各引擎的物理行标识（rowid/ctid），
			// MySQL 两者都没有则退化成 DELETE ... LIMIT —— 统一交给方言层构造。
			deleteLogQuery := dialect.Get().BatchDeleteSQL(
				"web_logs", "tenant_id=? AND user_code=? AND rule=?", batchSize,
			)
			result := global.GWAF_LOCAL_LOG_DB.Exec(deleteLogQuery, global.GWAF_TENANT_ID, global.GWAF_USER_CODE, tagName)

			if result.Error != nil {
				return fmt.Errorf("删除关联日志数据失败: %v", result.Error)
			}

			// 如果本批没有删除任何记录，说明已经删除完毕
			if result.RowsAffected == 0 {
				break
			}

			// 短暂休眠，避免长时间占用数据库
			time.Sleep(10 * time.Millisecond)
		}
	}

	return nil
}
