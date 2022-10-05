package request

type PageInfo struct {
	PageIndex int    `json:"pageIndex" form:"pageIndex"` //当前页面索引
	PageSize  int    `json:"pageSize" form:"pageSize"`   // 每页大小
	Keyword   string `json:"keyWord" form:"keyWord"`     //关键字
}
