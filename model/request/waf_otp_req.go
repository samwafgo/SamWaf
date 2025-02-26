package request

import "SamWaf/model/common/request"

type WafOtpAddReq struct {
	UserName string `json:"user_name" form:"user_name"`
	Url      string `json:"url" form:"url"`
	Secret   string `json:"secret" form:"secret"`
	Remarks  string `json:"remarks" form:"remarks"`
}
type WafOtpEditReq struct {
	Id       string `json:"id"`
	UserName string `json:"user_name" form:"user_name"`
	Url      string `json:"url" form:"url"`
	Secret   string `json:"secret" form:"secret"`
	Remarks  string `json:"remarks" form:"remarks"`
}
type WafOtpBindReq struct {
	UserName   string `json:"user_name" form:"user_name"`
	Url        string `json:"url" form:"url"`
	Secret     string `json:"secret" form:"secret"`
	Remarks    string `json:"remarks" form:"remarks"`
	SecretCode string `json:"secret_code" form:"secret_code"`
}
type WafOtpDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafOtpDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafOtpSearchReq struct {
	request.PageInfo
}
type WafOtpUnBindReq struct {
	SecretCode string `json:"secret_code" form:"secret_code"`
}
