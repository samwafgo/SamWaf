package request

import "SamWaf/model/common/request"

type WafDataRetentionEditReq struct {
	Id           string `json:"id"             form:"id"`
	RetainDays   int64  `json:"retain_days"    form:"retain_days"`
	RetainRows   int64  `json:"retain_rows"    form:"retain_rows"`
	CleanEnabled int64  `json:"clean_enabled"  form:"clean_enabled"`
	Remarks      string `json:"remarks"        form:"remarks"`
}

type WafDataRetentionDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafDataRetentionSearchReq struct {
	request.PageInfo
}
