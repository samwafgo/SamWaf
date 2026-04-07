package response

// TableColumnInfo 表字段信息
type TableColumnInfo struct {
	Cid        int    `json:"cid"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	NotNull    bool   `json:"not_null"`
	DefaultVal string `json:"default_val"`
	PrimaryKey bool   `json:"primary_key"`
}

// TableIndexColumnInfo 索引列信息
type TableIndexColumnInfo struct {
	SeqNo int    `json:"seq_no"`
	Cid   int    `json:"cid"`
	Name  string `json:"name"`
}

// TableIndexInfo 表索引信息
type TableIndexInfo struct {
	Name    string                 `json:"name"`
	Unique  bool                   `json:"unique"`
	Origin  string                 `json:"origin"`
	Columns []TableIndexColumnInfo `json:"columns"`
}

// TableInfo 单张表的完整信息
type TableInfo struct {
	TableName string            `json:"table_name"`
	RowCount  int64             `json:"row_count"`
	DataSize  int64             `json:"data_size"` // 字节
	Columns   []TableColumnInfo `json:"columns"`
	Indexes   []TableIndexInfo  `json:"indexes"`
}

// WafDbTableInfoResp 数据库表信息响应
type WafDbTableInfoResp struct {
	DbType string      `json:"db_type"`
	Tables []TableInfo `json:"tables"`
}
