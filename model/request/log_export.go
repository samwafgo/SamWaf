package request

type LogExportCreateReq struct {
	Format    string   `json:"format" form:"format"`
	Tables    []string `json:"tables" form:"tables"`
	RangeMode string   `json:"range_mode" form:"range_mode"`
	StartTime string   `json:"start_time" form:"start_time"`
	EndTime   string   `json:"end_time" form:"end_time"`
	RequestID string   `json:"request_id" form:"request_id"`
}

type LogExportListReq struct {
	PageIndex int    `json:"page" form:"page"`
	PageSize  int    `json:"page_size" form:"page_size"`
	SortBy    string `json:"sort_by" form:"sort_by"`
	SortOrder string `json:"sort_order" form:"sort_order"`
}

type LogExportDownloadReq struct {
	Ticket string `json:"ticket" form:"ticket"`
}
