package request

type WafSensitiveEditReq struct {
	Id      string `json:"id"`
	Type    int    `json:"type" form:"type"`         //敏感词类型
	Content string `json:"content" form:"content"  ` //内容
	Remarks string `json:"remarks" form:"remarks"  ` //备注
}