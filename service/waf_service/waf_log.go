package waf_service

import (
	"SamWaf/common/validfield"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type WafLogService struct{}

var WafLogServiceApp = new(WafLogService)

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	global.GWAF_LOCAL_LOG_DB.Create(log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(req request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	}

	return weblog, nil
}
func (receiver *WafLogService) GetListApi(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog

	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")
	/*强制索引*/
	var forceIndex = "web_logs"
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}

	//where字段
	{
		whereField = whereField + " (unix_add_time>=? and unix_add_time<=?)"
		if len(req.HostCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " host_code=? "
		}
		if len(req.Rule) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " rule=? "
		}
		if len(req.ReqUuid) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " req_uuid=? "
		}
		if len(req.Action) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " action=? "
		}
		if len(req.SrcIp) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " src_ip=? "
		}
		if len(req.StatusCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " status_code=? "
		}
		if len(req.Method) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " method=? "
		}
		if len(req.LogOnlyMode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " log_only_mode=? "
		}
		for _, by := range splitFilterBys {

			if len(by) > 0 {
				if !validfield.IsValidWebLogFilterField(by) {
					return nil, 0, errors.New("输入过滤字段不合法")
				}
				if len(whereField) > 0 {
					whereField = whereField + " and "
				}
				if by == "guest_identification" {
					by = "guest_id_entification"
				}
				whereField = whereField + " " + by + " like ? "
			}
		}
	}
	//强制索引
	{
		if strings.Contains(whereField, "unix_add_time") && !strings.Contains(whereField, "src_ip") {
			forceIndex = "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code"
		} else if strings.Contains(whereField, "src_ip") {
			forceIndex = "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code_ip"
		}
	}

	// 将字符串转换为 int64 类型
	unixBegin, err := strconv.ParseInt(req.UnixAddTimeBegin, 10, 64)
	if err != nil {
		fmt.Println("Error converting UnixAddTimeBegin to int64:", err)

	}

	unixEnd, err := strconv.ParseInt(req.UnixAddTimeEnd, 10, 64)
	if err != nil {
		fmt.Println("Error converting UnixAddTimeEnd to int64:", err)

	}

	//where字段赋值
	{
		whereValues = append(whereValues, unixBegin)
		whereValues = append(whereValues, unixEnd)
		if len(req.HostCode) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
		if len(req.Rule) > 0 {
			whereValues = append(whereValues, req.Rule)
		}
		if len(req.ReqUuid) > 0 {
			whereValues = append(whereValues, req.ReqUuid)
		}
		if len(req.Action) > 0 {
			whereValues = append(whereValues, req.Action)
		}
		if len(req.SrcIp) > 0 {
			whereValues = append(whereValues, req.SrcIp)
		}
		if len(req.StatusCode) > 0 {
			whereValues = append(whereValues, req.StatusCode)
		}
		if len(req.Method) > 0 {
			whereValues = append(whereValues, req.Method)
		}
		if len(req.LogOnlyMode) > 0 {
			whereValues = append(whereValues, req.LogOnlyMode)
		}
		for _, val := range splitFilterValues {
			if len(val) > 0 {
				whereValues = append(whereValues, "%"+val+"%")
			}
		}
	}

	orderInfo := ""

	/**
	排序
	*/
	if receiver.isValidSortField(req.SortBy) {
		if req.SortDescending == "desc" {
			orderInfo = req.SortBy + " desc"
		} else {
			orderInfo = req.SortBy + " asc"
		}
	} else {
		return nil, 0, errors.New("输入排序字段不合法")
	}
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Where(whereField, whereValues...).Count(&total)
	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Table(forceIndex).Where(whereField, whereValues...).Count(&total)

	}
	return weblogs, total, nil
}
func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) DeleteHistory(day string) {
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", day).Delete(&innerbean.WebLog{})
}

// GetUnixTimeByCounter 依据开始时间和到期时间获取一个最新的时间戳
func (receiver *WafLogService) GetUnixTimeByCounter(lastStartCreateUnix int64, lastEndCreateUnix int64) innerbean.WebLog {
	var weblog innerbean.WebLog
	forceIndex := "web_logs INDEXED BY  idx_web_time_desc_tenant_user_code"
	global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Where("unix_add_time>=? and unix_add_time<?", lastStartCreateUnix, lastEndCreateUnix).Order("unix_add_time desc").Limit(1).Find(&weblog)

	return weblog
}

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
	if err := global.GWAF_LOCAL_DB.Raw(query, params...).Scan(&results).Error; err != nil {
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
	if err := global.GWAF_LOCAL_DB.Raw(countQuery, countParams...).Scan(&total).Error; err != nil {
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
	if err := global.GWAF_LOCAL_DB.Raw(query, params...).Scan(&results).Error; err != nil {
		return nil, err
	}

	return results, nil
}

/*
*
判断是否合法
*/
func (receiver *WafLogService) isValidSortField(field string) bool {
	var allowedSortFields = []string{"time_spent", "create_time", "unix_add_time"}

	for _, allowedField := range allowedSortFields {
		if field == allowedField {
			return true
		}
	}
	return false
}
