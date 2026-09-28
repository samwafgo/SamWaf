package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"fmt"
	"strings"
	"sync"
	"time"

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
	// 解析当前分片的三层表：安全事件 → 访问日志 → 存量 web_logs，按 req_uuid 逐层点查。
	// 事件双写了窄行，内容一致，但事件表保留期更长，优先从它读。
	// 分区标识为空或 auto 时先按识别码定位分区：详情最常见的来路就是
	// 用户手里只有一串识别码，不知道那次访问落在哪个分区
	shardName := ResolveDetailShard(req.CurrrentDbName, req.REQ_UUID)
	tier := wafdb.ResolveTierTables(shardName)
	found := false
	for _, table := range []string{tier.Event, tier.Access, tier.WebLog} {
		if table == "" {
			continue
		}
		sel := webLogSelect(tier.DB, shardName, table, getWebLogDetailColumns(), "detail")
		res := tier.DB.Table(table).Select(sel).Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
		if res.Error != nil {
			return weblog, fmt.Errorf("查询日志详情失败: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			found = true
			break
		}
	}
	if !found {
		return weblog, nil
	}
	// 告诉界面这条是在哪个分区找到的：auto 时用户并没有选分区，得有个地方说清楚
	weblog.ShardName = shardName
	if weblog.ShardName == "" {
		weblog.ShardName = wafdb.LiveLogName()
	}
	// 报文单独存在 event_payload 里，按主键点查补回来；没有报文行的（正常请求未采样）保持窄字段
	FillShardPayloads(shardName, []*innerbean.WebLog{&weblog})
	return weblog, nil
}

// GetListApi 日志列表查询。条件组装、分区解析与跨分区扇出都在 waf_log_query.go，
// 这里保留旧签名给不关心「这次查了哪些分区」的调用方。
func (receiver *WafLogService) GetListApi(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	rows, total, _, err := receiver.GetListApiWithMeta(req)
	return rows, total, err
}

func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	// tenant/user 由 before_query 自动追加，这里只传 host_code（占位符与参数数须一致，避免参数顺移）
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ?", log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ?", log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}

// DeleteHistory 分层保留期清理：
//   - security_event 与 web_logs（存量，不再写入）按「日志保留天数」删
//   - access_log 按 access_log_retention_days 删（更短）
//   - event_payload 跟属主走：kind=event 随安全事件，kind=sample 只留 30 天，
//     kind=watch（观察名单全量留痕）只留 watchPayloadRetentionDays 天
//
// 三张新表都带同格式的 create_time，按各自条件删，不必回表对 req_uuid。
func (receiver *WafLogService) DeleteHistory(securityDay, accessDay string) {
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", securityDay).Delete(&innerbean.WebLog{})
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", securityDay).Delete(&model.SecurityEvent{})
	if err := global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", accessDay).
		Delete(&model.AccessLog{}).Error; err != nil {
		zlog.Warn("清理过期访问日志失败", "截止", accessDay, "error", err.Error())
	}
	sampleDay := time.Now().AddDate(0, 0, -sampleRetentionDays).Format("2006-01-02 15:04")
	watchDay := time.Now().AddDate(0, 0, -watchPayloadRetentionDays).Format("2006-01-02 15:04")
	if err := global.GWAF_LOCAL_LOG_DB.
		Where("(kind = ? and create_time < ?) or (kind = ? and create_time < ?) or (kind = ? and create_time < ?) or (kind = '' and create_time < ?)",
			"event", securityDay, "sample", sampleDay, "watch", watchDay, securityDay).
		Delete(&model.EventPayload{}).Error; err != nil {
		zlog.Warn("清理过期报文失败", "截止", securityDay, "error", err.Error())
	}
}

// sampleRetentionDays 采样负样本池的保留天数（D2）。比 access_log 独立：它喂的是 AI 训练。
const sampleRetentionDays = 30

// watchPayloadRetentionDays 观察名单全量留痕报文的保留天数（D9）。窄行仍随 access_log 保留期。
const watchPayloadRetentionDays = 7

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
