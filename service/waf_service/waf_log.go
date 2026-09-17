package waf_service

import (
	"SamWaf/common/validfield"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"
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
	webLogListSelectCache   []string
	webLogDetailSelectCache []string

	// webLogShardSelect 每个分片一份可用列，key = 分片标识|表名|用途。
	webLogShardSelect sync.Map
)

// getWebLogListColumns 动态从 WebLog 结构体反射出列名并排除大字段，结果缓存复用。
func getWebLogListColumns() []string {
	webLogListSelectOnce.Do(func() {
		webLogListSelectCache = columnsExcluding(&innerbean.WebLog{}, listExcludeColumns)
	})
	return webLogListSelectCache
}

// getWebLogDetailColumns 详情查询字段，包含文本 body 类字段，排除 blob。
func getWebLogDetailColumns() []string {
	webLogDetailSelectOnce.Do(func() {
		webLogDetailSelectCache = columnsExcluding(&innerbean.WebLog{}, detailExcludeColumns)
	})
	return webLogDetailSelectCache
}

// webLogSelect 给出这个分片上真正查得到的列。
//
// 归档分片是分库那一刻的结构快照，之后给 web_logs 加的列它没有；而 SELECT 是按当前结构体
// 反射出来的显式列名，少一列整条查询就报错。偏偏同一次请求里的 Count 不带列、照样数得出来，
// 页面于是变成「有分页、没数据」，错误还被 Find 吞掉，查都无从查起。
// 所以按分片实际存在的列取一次交集，结果按分片缓存（归档分片的结构不会再变）。
func webLogSelect(db *gorm.DB, shard, table string, want []string, usage string) string {
	key := shard + "|" + table + "|" + usage
	if v, ok := webLogShardSelect.Load(key); ok {
		return v.(string)
	}
	sel := strings.Join(want, ", ")
	if cols, err := dialect.Get().ColumnInfo(db, table); err == nil && len(cols) > 0 {
		have := make(map[string]bool, len(cols))
		for _, c := range cols {
			have[strings.ToLower(c.Name)] = true
		}
		kept := make([]string, 0, len(want))
		var missing []string
		for _, w := range want {
			if have[w] {
				kept = append(kept, w)
				continue
			}
			missing = append(missing, w)
		}
		// 一列都对不上多半是取列信息取错了表，这时宁可按结构体来，别把查询改成空
		if len(kept) > 0 {
			sel = strings.Join(kept, ", ")
			if len(missing) > 0 {
				zlog.Info("归档分片缺列，本次查询跳过", "table", table, "columns", strings.Join(missing, ","))
			}
		}
	}
	webLogShardSelect.Store(key, sel)
	return sel
}

// columnsExcluding 通过 GORM schema 解析模型字段，返回排除指定列后的列名（保持结构体顺序）。
func columnsExcluding(model interface{}, excludeDBNames map[string]bool) []string {
	s, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		return []string{"*"}
	}
	cols := make([]string, 0, len(s.Fields))
	for _, field := range s.Fields {
		if field.DBName == "" || excludeDBNames[field.DBName] {
			continue
		}
		cols = append(cols, field.DBName)
	}
	return cols
}

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	//必须传指针：WebLog.TASK_FLAG 带 gorm:"default:-1" 标签，按值 Create 遇零值回写默认值会 panic（#885 同类）
	global.GWAF_LOCAL_LOG_DB.Create(&log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(req request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	// 解析当前应查询的日志连接与表（live 或历史分片：SQLite 历史文件 / MySQL 历史表）
	logDB, logTable := wafdb.ResolveLogDB(req.CurrrentDbName)
	sel := webLogSelect(logDB, req.CurrrentDbName, logTable, getWebLogDetailColumns(), "detail")
	if err := logDB.Table(logTable).Select(sel).Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog).Error; err != nil {
		return weblog, fmt.Errorf("查询日志详情失败: %w", err)
	}
	// 报文单独存在 event_payload 里，按主键点查补回来
	FillShardPayloads(req.CurrrentDbName, []*innerbean.WebLog{&weblog})
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
	sel := webLogSelect(logDB, req.CurrrentDbName, logTable, getWebLogListColumns(), "list")
	// 错误必须往上抛：吞掉它就只剩「有分页、没数据」，连从哪查起都不知道
	if err := logDB.Select(sel).Table(forceIndex).Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs).Error; err != nil {
		return nil, 0, fmt.Errorf("查询日志失败: %w", err)
	}
	if err := logDB.Table(forceIndex).Where(whereField, whereValues...).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("统计日志条数失败: %w", err)
	}
	return weblogs, total, nil
}
func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	// tenant/user 由 before_query 自动追加，这里只传 host_code（占位符与参数数须一致，避免参数顺移）
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ?", log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ?", log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) DeleteHistory(day string) {
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", day).Delete(&innerbean.WebLog{})
	// 报文表自带同格式的 create_time，按同一条件删，不必回表对 req_uuid
	if err := global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", day).
		Delete(&model.EventPayload{}).Error; err != nil {
		zlog.Warn("清理过期报文失败", "截止", day, "error", err.Error())
	}
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
