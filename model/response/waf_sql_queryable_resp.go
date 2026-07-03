package response

// QueryableColumn 可查询列（已剔除敏感列）。
type QueryableColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// QueryableTable 可查询表及其可见列。
type QueryableTable struct {
	TableName string            `json:"table_name"`
	Columns   []QueryableColumn `json:"columns"`
}

// WafSqlQueryableResp 「取可查表/列」接口响应，仅供前端向导下拉使用：
// 不含敏感表、不含敏感列，也不返回行数/索引等额外结构信息。
type WafSqlQueryableResp struct {
	DbType string           `json:"db_type"`
	Tables []QueryableTable `json:"tables"`
}
