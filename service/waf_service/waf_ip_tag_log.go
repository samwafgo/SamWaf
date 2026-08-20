package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	// attackTagExcludeMax 排除名单条数上限：条件是逐项展开的，条数直接影响每行的比较次数
	// （97 万行实测：3 项 159ms、20 项 240ms），给个上限免得有人贴几百个进来把查询拖垮
	attackTagExcludeMax = 30
	// attackTagMaxLen 与 ip_tags.ip_tag 列宽一致，超长的本来也匹配不到任何数据
	attackTagMaxLen = 255
)

// attackTagBadChars 标签里不该出现的字符：引号/反引号/分号/反斜杠是 SQL 与转义的常见载体。
// 真实规则名（如「静态文件安全检查: 文件未找到」「OWASP:942100」「RCE:存在OS命令注入」）都不含这些。
const attackTagBadChars = "'\"`;\\"

// IsValidAttackTagExcludeItem 校验单个排除标签是否合法。
// 标签在 SQL 里始终是绑定参数、不参与拼接，这里是纵深防御：把引号、注释符、控制字符
// 这类明显不属于规则名的东西挡在配置层，顺带保证不会有人用超长/超多的值把查询拖垮。
func IsValidAttackTagExcludeItem(tag string) bool {
	if tag == "" || len(tag) > attackTagMaxLen {
		return false
	}
	if strings.ContainsAny(tag, attackTagBadChars) {
		return false
	}
	// 控制字符（含换行、制表）一律不允许
	for _, r := range tag {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	// SQL 注释符
	for _, bad := range []string{"--", "/*", "*/", "#"} {
		if strings.Contains(tag, bad) {
			return false
		}
	}
	return true
}

// ValidateAttackTagExclude 校验整条配置（逗号分隔），返回第一个不合法的项。
// 供管理端保存配置时调用：宁可让用户当场改，也不要写进库以后被静默丢弃。
func ValidateAttackTagExclude(value string) (string, bool) {
	count := 0
	for _, t := range strings.Split(value, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !IsValidAttackTagExcludeItem(t) {
			return t, false
		}
		count++
		if count > attackTagExcludeMax {
			return t, false
		}
	}
	return "", true
}

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
		// 配置值来自管理端输入：这里再清洗一次（写入时已校验，防的是直接改库/改配置文件的情况）。
		// 标签本身是参数绑定的，不会拼进 SQL；非法值直接丢弃而不是报错，避免一条脏数据让整页查不出来。
		if !IsValidAttackTagExcludeItem(t) {
			zlog.Warn("attack_tag_exclude 含非法标签，已忽略", zap.String("tag", t))
			continue
		}
		seen[t] = true
		tags = append(tags, t)
		if len(tags) >= attackTagExcludeMax+1 { // +1 是固定的"正常"
			break
		}
	}
	return tags
}

// benignNotCond / benignIsCond 生成「不属于/属于排除名单」的条件。
// 用 <> 链而不是 NOT IN：97 万行实测 NOT IN(3项) 198ms、<> 链 159ms —— SQLite 对 IN 会建
// 临时索引去探查，值少时探查开销比逐个比较还大。列表为空时退化成恒真/恒假。
// 标签值来自用户配置，一律参数绑定，不拼进 SQL。
func benignNotCond(n int) string {
	if n <= 0 {
		return "1=1"
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, "ip_tag<>?")
	}
	return "(" + strings.Join(parts, " AND ") + ")"
}

func benignIsCond(n int) string {
	if n <= 0 {
		return "1=0"
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, "ip_tag=?")
	}
	return "(" + strings.Join(parts, " OR ") + ")"
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
	notBenign := benignNotCond(len(tags))
	isBenign := benignIsCond(len(tags))
	// 聚合去重拼接：SQLite/MySQL 用 GROUP_CONCAT，PostgreSQL 用 string_agg
	ipTotalTagExpr := dialect.Get().GroupConcatDistinct("CASE WHEN " + notBenign + " THEN ip_tag END")
	query := `
	SELECT
		tenant_id,
		user_code,
		ip,
		SUM(CASE WHEN ` + isBenign + ` THEN cnt ELSE 0 END) AS pass_num,
		SUM(CASE WHEN ` + notBenign + ` THEN cnt ELSE 0 END) AS deny_num,
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
		SUM(CASE WHEN ` + notBenign + ` THEN cnt ELSE 0 END) > 0 
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

	// 获取总记录数：等价于「至少有一条非排除标签且 cnt>0」的 IP 数。
	// 用 COUNT(DISTINCT ip) 而不是 GROUP BY+HAVING 子查询：97 万行实测 572ms -> 207ms，
	// 因为过滤发生在分组之前，只有少量风险行需要去重（cnt 是计数器不会为负，两者结果一致）。
	countQuery := `
	SELECT
		COUNT(DISTINCT ip) AS total
	FROM
		ip_tags
	WHERE tenant_id=? and user_code=? and cnt>0 and ` + notBenign

	// 动态添加过滤条件
	if req.Rule != "" {
		countQuery += " AND ip_tag = ?"
	}
	if req.SrcIp != "" {
		countQuery += " AND ip = ?"
	}

	// 获取总记录数参数（按占位符顺序：tenant/user -> 排除名单 -> [rule] -> [ip]）
	countParams := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE}
	countParams = appendTags(countParams, tags)
	if req.Rule != "" {
		countParams = append(countParams, req.Rule)
	}
	if req.SrcIp != "" {
		countParams = append(countParams, req.SrcIp)
	}

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
	notBenign := benignNotCond(len(tags))
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
WHERE %s and tenant_id=? and user_code=?
	GROUP BY
    tenant_id,
    ip_tag
order by  sum(cnt) desc
`, labelExpr, notBenign)

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
