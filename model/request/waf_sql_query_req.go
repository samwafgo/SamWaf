package request

type WafSqlQueryReq struct {
	DbType string `json:"db_type" form:"db_type"` // 数据库类型：local, log, stats
	Sql    string `json:"sql" form:"sql"`         // SQL 查询语句
	Limit  int    `json:"limit" form:"limit"`     // 返回记录数限制，默认 1000
}
