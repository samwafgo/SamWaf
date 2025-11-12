package waf_service

import (
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

type WafSqlQueryService struct{}

var WafSqlQueryServiceApp = new(WafSqlQueryService)

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
