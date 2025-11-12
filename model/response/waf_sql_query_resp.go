package response

type WafSqlQueryResp struct {
	Columns []string                 `json:"columns"` // 列名列表
	Data    []map[string]interface{} `json:"data"`    // 数据行列表
	Total   int                      `json:"total"`   // 总记录数
}
