package request

// WafSqlFilter 结构化查询条件（单条），多条之间以 AND 连接。
// 安全约束（三者缺一不可）：
//   - Column 必须精确命中目标表的「可见列白名单」（真实列 − 敏感列）；
//   - Op 必须取自固定运算符白名单（见 service 层 allowedSqlOps）；
//   - Value 一律通过 GORM 参数（?）绑定，绝不拼接进 SQL 文本。
type WafSqlFilter struct {
	Column string      `json:"column"` // 条件列（白名单校验）
	Op     string      `json:"op"`     // 运算符：= != > >= < <= like in
	Value  interface{} `json:"value"`  // 绑定值（in 运算符时为数组）
}

// WafSqlQueryReq 结构化数据查询请求。
// 后端不再接收任何裸 SQL：表 / 列 / 运算符全部走服务端白名单校验后由 GORM 链式构造，
// 值全部参数化绑定；前端也不提供 SQL 输入框。
type WafSqlQueryReq struct {
	DbType  string         `json:"db_type" form:"db_type"` // 数据库：local, log, stats
	Table   string         `json:"table" form:"table"`     // 目标表（单选，白名单校验）
	Mode    string         `json:"mode" form:"mode"`       // list=查行 / count=计数，默认 list
	Columns []string       `json:"columns" form:"columns"` // 查询列（可空；空=全部可见列，仅 list 生效）
	Filters []WafSqlFilter `json:"filters" form:"filters"` // 结构化条件（可空；为空即无 WHERE）
	Top     int            `json:"top" form:"top"`         // 返回行数上限（仅 list，默认 1000、封顶 1000）
}
