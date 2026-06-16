package waf_service

import (
	"SamWaf/common/validfield"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm/schema"
)

type WafLogService struct{}

var WafLogServiceApp = new(WafLogService)

// listExcludeColumns 列表查询排除的列：大文本字段和原始 blob 字段
var listExcludeColumns = map[string]bool{
	"body": true, "res_body": true, "post_form": true,
	"src_byte_body": true, "src_byte_res_body": true, "src_url": true,
}

// detailExcludeColumns 详情查询排除的列：仅排除原始 blob 字段，保留文本 body 类字段
var detailExcludeColumns = map[string]bool{
	"src_byte_body": true, "src_byte_res_body": true, "src_url": true,
}

var (
	webLogListSelectOnce    sync.Once
	webLogDetailSelectOnce  sync.Once
	webLogListSelectCache   string
	webLogDetailSelectCache string
)

// getWebLogListSelect 动态从 WebLog 结构体反射出列名并排除大字段，结果缓存复用。
// 新增字段会自动纳入，旧版本数据库缺列也不影响（GORM 会忽略不存在的列）。
func getWebLogListSelect() string {
	webLogListSelectOnce.Do(func() {
		webLogListSelectCache = buildSelectExcluding(&innerbean.WebLog{}, listExcludeColumns)
	})
	return webLogListSelectCache
}

// getWebLogDetailSelect 详情查询字段，包含文本 body 类字段，排除 blob。
func getWebLogDetailSelect() string {
	webLogDetailSelectOnce.Do(func() {
		webLogDetailSelectCache = buildSelectExcluding(&innerbean.WebLog{}, detailExcludeColumns)
	})
	return webLogDetailSelectCache
}

// buildSelectExcluding 通过 GORM schema 解析模型字段，返回排除指定列后的 SELECT 子句。
func buildSelectExcluding(model interface{}, excludeDBNames map[string]bool) string {
	s, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		return "*"
	}
	cols := make([]string, 0, len(s.Fields))
	for _, field := range s.Fields {
		if field.DBName == "" || excludeDBNames[field.DBName] {
			continue
		}
		cols = append(cols, field.DBName)
	}
	return strings.Join(cols, ", ")
}

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	global.GWAF_LOCAL_LOG_DB.Create(log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(req request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	// 解析当前应查询的日志连接与表（live 或历史分片：SQLite 历史文件 / MySQL 历史表）
	logDB, logTable := wafdb.ResolveLogDB(req.CurrrentDbName)
	logDB.Table(logTable).Select(getWebLogDetailSelect()).Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	return weblog, nil
}
func (receiver *WafLogService) GetListApi(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog

	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")
	// 解析当前应查询的日志连接与表（live 或历史分片：SQLite 历史文件 / MySQL 历史表）
	logDB, logTable := wafdb.ResolveLogDB(req.CurrrentDbName)
	/*强制索引*/
	var forceIndex = logTable
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
			forceIndex = dialect.Get().ForceIndexClause(logTable, "idx_web_time_desc_tenant_user_code")
		} else if strings.Contains(whereField, "src_ip") {
			forceIndex = dialect.Get().ForceIndexClause(logTable, "idx_web_time_desc_tenant_user_code_ip")
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
	logDB.Select(getWebLogListSelect()).Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
	logDB.Table(forceIndex).Where(whereField, whereValues...).Count(&total)
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
	forceIndex := dialect.Get().ForceIndexClause("web_logs", "idx_web_time_desc_tenant_user_code")
	global.GWAF_LOCAL_LOG_DB.Table(forceIndex).Where("unix_add_time>=? and unix_add_time<?", lastStartCreateUnix, lastEndCreateUnix).Order("unix_add_time desc").Limit(1).Find(&weblog)

	return weblog
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
