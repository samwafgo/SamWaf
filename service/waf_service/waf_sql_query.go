package waf_service

import (
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/wafdb/dialect"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type WafSqlQueryService struct{}

var WafSqlQueryServiceApp = new(WafSqlQueryService)

// ────────────────────────────────────────────────────────────────────────────
// 白名单：结构化查询的安全边界。后端不接收任何裸 SQL，一切按下列规则 fail-closed。
// ────────────────────────────────────────────────────────────────────────────

// sensitiveColumnSubstrings 敏感列名子串（小写包含匹配）。命中即从「可见列」中剔除：
// 既不能被 SELECT、也不能出现在 filters 条件里（因此无法用布尔盲注逐字节套取）。
// 说明：
//   - "key" 用于兜住 SslConfig.key_content、SslOrder.apply_key、oplatform_keys.api_key
//     这类列名不含 private/secret 却是私钥/密钥的字段——宁可多藏（普通列被藏仅影响易用性），
//     绝不能漏藏机密（漏一个就是私钥/口令外泄）。
//   - "private" 兜住 PrivateInfo.private_value（值不含 key）。
//
// 新增敏感字段命名时，如落在这些子串之外，需在此同步补充。
var sensitiveColumnSubstrings = []string{
	"password", "passwd", "pwd", "secret", "token",
	"private", "salt", "key", "credential", "cipher",
}

// sensitiveTableSubstrings 敏感表名子串（小写包含匹配）。命中即整表不可查、不可枚举、
// 连行数/结构都不暴露——作为列级过滤之外的域级兜底（认证 / 密钥 / 证书相关表）。
// 用子串而非精确表名，避免因 GORM 复数命名 / 前缀差异导致漏配。
var sensitiveTableSubstrings = []string{
	"account",        // accounts, account_pwd_histories（口令/历史口令指纹/访问码）
	"otp",            // otps（2FA 密钥）
	"ssl",            // sslconfigs, sslorders, sslexpires（证书私钥 key_content/apply_key/result_private_key）
	"private",        // private_infos（私密信息）
	"oplatform",      // oplatform_keys（API Key）
	"notify_channel", // notify_channels（渠道 secret / access_token）
	"notifychannel",
	"http_auth", // http_auth_base_configs（访问密码）
	"httpauth",
	"token",  // 任何令牌表
	"secret", // 任何以 secret 命名的表
	"config", // system_configs / *config* 键值配置表（可能明文存密钥）
	"plugin", // waf_plugin_* 插件配置/日志（参数/值/IO 可能含凭证）
}

// allowedSqlOps 结构化条件允许的运算符白名单。
var allowedSqlOps = map[string]bool{
	"=": true, "!=": true, ">": true, ">=": true,
	"<": true, "<=": true, "like": true, "in": true,
}

// 资源上限：防止超大结构化请求造成的内存/DB 资源消耗。
const (
	maxSqlFilters  = 50  // filters 条数上限
	maxSqlInValues = 500 // in 运算符数组元素上限
)

func isSensitiveColumn(name string) bool {
	l := strings.ToLower(name)
	for _, s := range sensitiveColumnSubstrings {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func isSensitiveTable(name string) bool {
	l := strings.ToLower(name)
	for _, s := range sensitiveTableSubstrings {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// hasOpaqueValueColumn 判断表是否为键值/EAV 形态（含名为 value/params 的通用值列）。
// 这类表把任意（可能是机密的）数据塞进一个通用列，列名子串分类器无法甄别其内容，
// 故整表按敏感处理。典型：system_configs.value 明文存 gpt_token / zerossl_eab_hmac_key /
// debug_pwd 等密钥；waf_plugin_system_configs.value、waf_plugin_configs.params 同理。
func hasOpaqueValueColumn(cols []dialect.ColumnMeta) bool {
	for _, c := range cols {
		switch strings.ToLower(c.Name) {
		case "value", "params":
			return true
		}
	}
	return false
}

// pickDB 按类型返回目标库实例。
func (receiver *WafSqlQueryService) pickDB(dbType string) (*gorm.DB, error) {
	switch dbType {
	case "local":
		return global.GWAF_LOCAL_DB, nil
	case "log":
		return global.GWAF_LOCAL_LOG_DB, nil
	case "stats":
		return global.GWAF_LOCAL_STATS_DB, nil
	default:
		return nil, errors.New("无效的数据库类型")
	}
}

// resolveQueryableColumns 校验表可查并返回其「可见列」（真实列 − 敏感列）。
// fail-closed：命中敏感表、表不存在（未精确命中真实表清单）、或无可见列时返回错误。
// 先用 ListTables 精确匹配再取列信息，确保传入下游 schema 查询的一定是真实表名。
func (receiver *WafSqlQueryService) resolveQueryableColumns(db *gorm.DB, table string) (string, []string, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return "", nil, errors.New("必须指定查询表")
	}
	if isSensitiveTable(table) {
		return "", nil, fmt.Errorf("表不可查询: %s", table)
	}
	tables, err := dialect.Get().ListTables(db)
	if err != nil {
		return "", nil, fmt.Errorf("获取表清单失败: %w", err)
	}
	matched := ""
	for _, t := range tables {
		if t == table {
			matched = t
			break
		}
	}
	if matched == "" {
		return "", nil, fmt.Errorf("表不存在或不可查询: %s", table)
	}
	cols, err := dialect.Get().ColumnInfo(db, matched)
	if err != nil {
		return "", nil, fmt.Errorf("获取列信息失败: %w", err)
	}
	// EAV/键值表整表 fail-closed（value/params 通用值列可能承载明文机密）
	if hasOpaqueValueColumn(cols) {
		return "", nil, fmt.Errorf("表不可查询（键值型表可能含机密）: %s", matched)
	}
	var visible []string
	for _, c := range cols {
		if isSensitiveColumn(c.Name) {
			continue
		}
		visible = append(visible, c.Name)
	}
	if len(visible) == 0 {
		return "", nil, fmt.Errorf("表无可查询列: %s", matched)
	}
	return matched, visible, nil
}

// buildSqlWhere 依据白名单运算符构造参数化 WHERE 表达式。
// col 已由调用方校验为可见列；op 取自 allowedSqlOps；value 一律经 GORM ? 绑定，绝不拼接。
func buildSqlWhere(col, op string, value interface{}) (clause.Expression, error) {
	column := clause.Column{Name: col}
	switch op {
	case "=":
		return clause.Eq{Column: column, Value: value}, nil
	case "!=":
		return clause.Neq{Column: column, Value: value}, nil
	case ">":
		return clause.Gt{Column: column, Value: value}, nil
	case ">=":
		return clause.Gte{Column: column, Value: value}, nil
	case "<":
		return clause.Lt{Column: column, Value: value}, nil
	case "<=":
		return clause.Lte{Column: column, Value: value}, nil
	case "like":
		return clause.Like{Column: column, Value: value}, nil
	case "in":
		vals, ok := value.([]interface{})
		if !ok {
			return nil, errors.New("in 条件的值必须是数组")
		}
		if len(vals) == 0 {
			return nil, errors.New("in 条件的值不能为空数组")
		}
		if len(vals) > maxSqlInValues {
			return nil, fmt.Errorf("in 条件元素过多（上限 %d）", maxSqlInValues)
		}
		return clause.IN{Column: column, Values: vals}, nil
	default:
		return nil, fmt.Errorf("不允许的运算符: %s", op)
	}
}

// GetTableInfo 获取指定数据库的表结构信息（列、索引、行数）。
// 已收敛到白名单：跳过敏感表、剔除敏感列，避免结构页泄露认证/密钥表的结构。
func (receiver *WafSqlQueryService) GetTableInfo(req request.WafDbTableInfoReq) (response.WafDbTableInfoResp, error) {
	var result response.WafDbTableInfoResp
	result.DbType = req.DbType

	db, err := receiver.pickDB(req.DbType)
	if err != nil {
		return result, err
	}

	// 获取所有用户表
	tableNames, err := dialect.Get().ListTables(db)
	if err != nil {
		return result, fmt.Errorf("获取表列表失败: %w", err)
	}

	for _, tableName := range tableNames {
		// 敏感表（认证/密钥/证书域）不在结构页暴露
		if isSensitiveTable(tableName) {
			continue
		}
		tableInfo := response.TableInfo{
			TableName: tableName,
		}

		// 获取字段信息（剔除敏感列，与可查询范围保持一致）
		cols, colErr := dialect.Get().ColumnInfo(db, tableName)
		// EAV/键值表整表跳过，不在结构页暴露
		if colErr == nil && hasOpaqueValueColumn(cols) {
			continue
		}
		if colErr == nil {
			for _, c := range cols {
				if isSensitiveColumn(c.Name) {
					continue
				}
				tableInfo.Columns = append(tableInfo.Columns, response.TableColumnInfo{
					Cid:        c.Cid,
					Name:       c.Name,
					Type:       c.Type,
					NotNull:    c.NotNull,
					DefaultVal: c.DefaultVal,
					PrimaryKey: c.PrimaryKey,
				})
			}
		}

		// 获取索引列表
		idxs, idxErr := dialect.Get().IndexInfo(db, tableName)
		if idxErr == nil {
			for _, idx := range idxs {
				idxInfo := response.TableIndexInfo{
					Name:   idx.Name,
					Unique: idx.Unique,
					Origin: idx.Origin,
				}
				for _, col := range idx.Columns {
					idxInfo.Columns = append(idxInfo.Columns, response.TableIndexColumnInfo{
						SeqNo: col.SeqNo,
						Cid:   col.Cid,
						Name:  col.Name,
					})
				}
				tableInfo.Indexes = append(tableInfo.Indexes, idxInfo)
			}
		}

		// 获取行数
		var count int64
		db.Table(tableName).Count(&count)
		tableInfo.RowCount = count
		// DataSize: 该 SQLite 编译版本不支持 dbstat 虚拟表，暂不查询数据大小

		result.Tables = append(result.Tables, tableInfo)
	}

	if result.Tables == nil {
		result.Tables = []response.TableInfo{}
	}
	return result, nil
}

// GetQueryableSchema 返回可查表及其可见列，供前端向导下拉使用（不含敏感表/敏感列）。
func (receiver *WafSqlQueryService) GetQueryableSchema(req request.WafDbTableInfoReq) (response.WafSqlQueryableResp, error) {
	var result response.WafSqlQueryableResp
	result.DbType = req.DbType
	result.Tables = []response.QueryableTable{}

	db, err := receiver.pickDB(req.DbType)
	if err != nil {
		return result, err
	}

	tables, err := dialect.Get().ListTables(db)
	if err != nil {
		return result, fmt.Errorf("获取表清单失败: %w", err)
	}

	for _, t := range tables {
		if isSensitiveTable(t) {
			continue
		}
		cols, colErr := dialect.Get().ColumnInfo(db, t)
		if colErr != nil {
			continue
		}
		// EAV/键值表不暴露给向导下拉
		if hasOpaqueValueColumn(cols) {
			continue
		}
		qt := response.QueryableTable{TableName: t, Columns: []response.QueryableColumn{}}
		for _, c := range cols {
			if isSensitiveColumn(c.Name) {
				continue
			}
			qt.Columns = append(qt.Columns, response.QueryableColumn{Name: c.Name, Type: c.Type})
		}
		if len(qt.Columns) == 0 {
			continue // 全部列敏感的表不暴露
		}
		result.Tables = append(result.Tables, qt)
	}
	return result, nil
}

// ExecuteQuery 结构化数据查询：表/列/运算符全部白名单校验，值全部参数化，由 GORM 链式构造。
// 支持 list（查行）与 count（计数）两种模式，天然兼容 SQLite/MySQL/SQLServer。
func (receiver *WafSqlQueryService) ExecuteQuery(req request.WafSqlQueryReq) (response.WafSqlQueryResp, error) {
	var result response.WafSqlQueryResp

	db, err := receiver.pickDB(req.DbType)
	if err != nil {
		return result, err
	}

	// 模式校验
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "list"
	}
	if mode != "list" && mode != "count" {
		return result, errors.New("无效的查询模式，仅支持 list 或 count")
	}
	result.Mode = mode
	result.Columns = []string{}
	result.Data = []map[string]interface{}{}

	// 表 + 可见列白名单（fail-closed）
	table, visibleCols, err := receiver.resolveQueryableColumns(db, req.Table)
	if err != nil {
		return result, err
	}
	colSet := make(map[string]bool, len(visibleCols))
	for _, c := range visibleCols {
		colSet[c] = true
	}

	// 列白名单（仅 list 生效；为空取全部可见列，绝不 SELECT *）
	var selectCols []string
	if mode == "list" {
		if len(req.Columns) == 0 {
			selectCols = visibleCols
		} else {
			for _, c := range req.Columns {
				if !colSet[c] {
					return result, fmt.Errorf("列不可查询或不存在: %s", c)
				}
				selectCols = append(selectCols, c)
			}
		}
	}

	// 结构化条件：列白名单 + op 白名单 + 值参数化
	if len(req.Filters) > maxSqlFilters {
		return result, fmt.Errorf("查询条件过多（上限 %d）", maxSqlFilters)
	}
	q := db.Table(table)
	for _, f := range req.Filters {
		if !colSet[f.Column] {
			return result, fmt.Errorf("条件列不可查询或不存在: %s", f.Column)
		}
		op := strings.ToLower(strings.TrimSpace(f.Op))
		if !allowedSqlOps[op] {
			return result, fmt.Errorf("不允许的运算符: %s", f.Op)
		}
		expr, buildErr := buildSqlWhere(f.Column, op, f.Value)
		if buildErr != nil {
			return result, buildErr
		}
		q = q.Where(expr)
	}

	// count 模式
	if mode == "count" {
		var total int64
		if err := q.Count(&total).Error; err != nil {
			return result, err
		}
		result.Total = total
		return result, nil
	}

	// list 模式
	top := req.Top
	if top <= 0 || top > 1000 {
		top = 1000
	}
	data := make([]map[string]interface{}, 0)
	if err := q.Select(selectCols).Limit(top).Find(&data).Error; err != nil {
		return result, err
	}
	// []byte → string，便于前端展示（与旧行为一致）
	for _, row := range data {
		for k, v := range row {
			if b, ok := v.([]byte); ok {
				row[k] = string(b)
			}
		}
	}
	result.Columns = selectCols
	result.Data = data
	result.Total = int64(len(data))
	return result, nil
}
