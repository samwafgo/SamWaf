package request

type WafDbTableInfoReq struct {
	DbType string `json:"db_type" form:"db_type"` // 数据库类型：local, log, stats
}
