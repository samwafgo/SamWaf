package waf_service

import (
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

type WafSqlQueryService struct{}

var WafSqlQueryServiceApp = new(WafSqlQueryService)

// GetTableInfo 获取指定数据库的所有表结构信息（列、索引、行数、数据大小）
func (receiver *WafSqlQueryService) GetTableInfo(req request.WafDbTableInfoReq) (response.WafDbTableInfoResp, error) {
	var result response.WafDbTableInfoResp
	result.DbType = req.DbType

	var db *gorm.DB
	switch req.DbType {
	case "local":
		db = global.GWAF_LOCAL_DB
	case "log":
		db = global.GWAF_LOCAL_LOG_DB
	case "stats":
		db = global.GWAF_LOCAL_STATS_DB
	default:
		return result, errors.New("无效的数据库类型")
	}

	// 获取所有用户表（排除 sqlite 内部表）
	tableRows, err := db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").Rows()
	if err != nil {
		return result, fmt.Errorf("获取表列表失败: %w", err)
	}
	var tableNames []string
	for tableRows.Next() {
		var name string
		if scanErr := tableRows.Scan(&name); scanErr == nil {
			tableNames = append(tableNames, name)
		}
	}
	tableRows.Close()

	for _, tableName := range tableNames {
		tableInfo := response.TableInfo{
			TableName: tableName,
		}

		// 获取字段信息（dflt_value 可能为 NULL，必须用 NullString 扫描）
		colRows, err := db.Raw("PRAGMA table_info(" + quoteSQLiteName(tableName) + ")").Rows()
		if err == nil {
			for colRows.Next() {
				var cid int
				var colName, colType string
				var notNull, pk int
				var dfltValue sql.NullString
				if scanErr := colRows.Scan(&cid, &colName, &colType, &notNull, &dfltValue, &pk); scanErr == nil {
					tableInfo.Columns = append(tableInfo.Columns, response.TableColumnInfo{
						Cid:        cid,
						Name:       colName,
						Type:       colType,
						NotNull:    notNull == 1,
						DefaultVal: dfltValue.String,
						PrimaryKey: pk > 0,
					})
				}
			}
			colRows.Close()
		}

		// 获取索引列表
		idxRows, err := db.Raw("PRAGMA index_list(" + quoteSQLiteName(tableName) + ")").Rows()
		if err == nil {
			for idxRows.Next() {
				var seq int
				var idxName, origin string
				var unique, partial int
				if scanErr := idxRows.Scan(&seq, &idxName, &unique, &origin, &partial); scanErr == nil {
					idxInfo := response.TableIndexInfo{
						Name:   idxName,
						Unique: unique == 1,
						Origin: origin,
					}
					// 获取该索引包含的列（name 列可能为 NULL，用 NullString 扫描）
					idxColRows, icErr := db.Raw("PRAGMA index_info(" + quoteSQLiteName(idxName) + ")").Rows()
					if icErr == nil {
						for idxColRows.Next() {
							var seqNo, cid int
							var idxColName sql.NullString
							if scanErr2 := idxColRows.Scan(&seqNo, &cid, &idxColName); scanErr2 == nil {
								idxInfo.Columns = append(idxInfo.Columns, response.TableIndexColumnInfo{
									SeqNo: seqNo,
									Cid:   cid,
									Name:  idxColName.String,
								})
							}
						}
						idxColRows.Close()
					}
					tableInfo.Indexes = append(tableInfo.Indexes, idxInfo)
				}
			}
			idxRows.Close()
		}

		// 获取行数
		var count int64
		countRow := db.Raw("SELECT COUNT(*) FROM " + quoteSQLiteName(tableName)).Row()
		if countRow != nil {
			_ = countRow.Scan(&count)
		}
		tableInfo.RowCount = count
		// DataSize: 该 SQLite 编译版本不支持 dbstat 虚拟表，暂不查询数据大小

		result.Tables = append(result.Tables, tableInfo)
	}

	if result.Tables == nil {
		result.Tables = []response.TableInfo{}
	}
	return result, nil
}

// quoteSQLiteName 对 SQLite 表名/索引名做双引号转义
func quoteSQLiteName(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func (receiver *WafSqlQueryService) ExecuteQuery(req request.WafSqlQueryReq) (response.WafSqlQueryResp, error) {
	var result response.WafSqlQueryResp
	var db *gorm.DB

	// 验证并选择数据库
	switch req.DbType {
	case "local":
		db = global.GWAF_LOCAL_DB
	case "log":
		db = global.GWAF_LOCAL_LOG_DB
	case "stats":
		db = global.GWAF_LOCAL_STATS_DB
	default:
		return result, errors.New("无效的数据库类型")
	}

	// 验证 SQL 语句，只允许 SELECT 查询
	sqlLower := strings.ToLower(strings.TrimSpace(req.Sql))
	if !strings.HasPrefix(sqlLower, "select") {
		return result, errors.New("仅允许执行 SELECT 查询")
	}

	// 检查是否包含危险操作（使用单词边界匹配，避免误判字段名如 create_time、update_time）
	dangerousKeywords := []string{
		`\bdrop\b`, `\bdelete\b`, `\bupdate\b`, `\binsert\b`,
		`\btruncate\b`, `\balter\b`, `\bcreate\b`, `\bexec\b`,
		`\bexecute\b`, `\bpragma\b`, `\battach\b`,
	}
	for _, pattern := range dangerousKeywords {
		matched, err := regexp.MatchString(pattern, sqlLower)
		if err == nil && matched {
			return result, errors.New("查询包含不允许的操作: " + pattern)
		}
	}

	// 设置默认限制
	if req.Limit <= 0 || req.Limit > 1000 {
		req.Limit = 1000
	}

	// 添加 LIMIT 限制
	sql := req.Sql
	if !strings.Contains(sqlLower, "limit") {
		sql = sql + fmt.Sprintf(" LIMIT %d", req.Limit)
	}

	// 执行查询
	rows, err := db.Raw(sql).Rows()
	if err != nil {
		return result, err
	}
	defer rows.Close()

	// 获取列名
	columns, err := rows.Columns()
	if err != nil {
		return result, err
	}
	result.Columns = columns

	// 读取数据
	result.Data = make([]map[string]interface{}, 0)
	for rows.Next() {
		// 创建一个切片来存储当前行的值
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		// 扫描当前行
		if err := rows.Scan(valuePtrs...); err != nil {
			return result, err
		}

		// 构建 map
		rowMap := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// 处理 []byte 类型，转换为 string
			if b, ok := val.([]byte); ok {
				rowMap[col] = string(b)
			} else {
				rowMap[col] = val
			}
		}
		result.Data = append(result.Data, rowMap)
	}

	result.Total = len(result.Data)
	return result, nil
}
