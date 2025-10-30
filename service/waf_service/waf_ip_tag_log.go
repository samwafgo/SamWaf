package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"fmt"
	"time"
)

// GetAttackIpListApi 访问IP列表
func (receiver *WafLogService) GetAttackIpListApi(req request.WafAttackIpTagSearch) ([]model.AttackIPTag, int64, error) {
	var results []model.AttackIPTag
	var total int64

	// 获取本地时区偏移量（秒）
	_, offset := time.Now().Zone()
	offsetMinutes := offset / 60

	// 构建时区偏移修饰符
	var offsetModifier string
	if offsetMinutes >= 0 {
		offsetModifier = fmt.Sprintf("'+%d minutes'", offsetMinutes)
	} else {
		offsetModifier = fmt.Sprintf("'%d minutes'", offsetMinutes) // 负数自带负号
	}

	// 基础查询部分
	query := `
	SELECT 
		tenant_id,
		user_code,
		ip, 
		SUM(CASE WHEN ip_tag = '正常' THEN cnt ELSE 0 END) AS pass_num, 
		SUM(CASE WHEN ip_tag <> '正常' THEN cnt ELSE 0 END) AS deny_num,
		strftime('%Y-%m-%d %H:%M:%S', MIN(update_time), ` + offsetModifier + `) AS first_time, 
		strftime('%Y-%m-%d %H:%M:%S', MAX(update_time), ` + offsetModifier + `) AS latest_time,
		GROUP_CONCAT(DISTINCT CASE WHEN ip_tag <> '正常' THEN ip_tag END) AS ip_total_tag
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
		SUM(CASE WHEN ip_tag <> '正常' THEN cnt ELSE 0 END) > 0 
	ORDER BY 
		MAX(update_time) DESC
	LIMIT ? OFFSET ?`

	// 构建查询参数
	params := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE}

	// 添加 Rule 和 SrcIp 作为参数（如果提供了）
	if req.Rule != "" {
		params = append(params, req.Rule)
	}
	if req.SrcIp != "" {
		params = append(params, req.SrcIp)
	}

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
		SUM(CASE WHEN ip_tag <> '正常' THEN cnt ELSE 0 END) > 0
	) AS subquery`

	// 获取总记录数参数
	countParams := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE}
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
func (receiver *WafLogService) GetAllAttackIPTagListApi() ([]model.AllIPTag, error) {
	var results []model.AllIPTag

	// 基础查询部分
	query := ` 
SELECT  
    ip_tag as value,
	ip_tag || ' (' || sum(cnt) || ')' as label
    FROM
    "ip_tags"
WHERE ip_tag<>'正常'    and 	  tenant_id=? and user_code=? 
	GROUP BY 
    tenant_id, 
    ip_tag 
order by  sum(cnt) desc 
`

	// 构建查询参数
	params := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE}

	// 执行查询
	ipTagDB := global.GetIPTagDB() // 使用封装方法获取数据库连接
	if err := ipTagDB.Raw(query, params...).Scan(&results).Error; err != nil {
		return nil, err
	}

	return results, nil
}
