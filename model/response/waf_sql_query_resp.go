package response

type WafSqlQueryResp struct {
	Mode    string                   `json:"mode"`    // 回显模式：list / count
	Columns []string                 `json:"columns"` // 列名列表（list 模式）
	Data    []map[string]interface{} `json:"data"`    // 数据行列表（list 模式）
	Total   int64                    `json:"total"`   // list=返回行数；count=符合条件的总记录数
}
