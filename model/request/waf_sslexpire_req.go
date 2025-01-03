package request

import "SamWaf/model/common/request"

type WafSslExpireAddReq struct {
	Domain   string `json:"domain" form:"domain"`
	Port     int    `json:"port" form:"port"`
	VisitLog string `json:"visit_log" form:"visit_log"`
	Status   string `json:"status" form:"status"`
}
type WafSslExpireEditReq struct {
	Id string `json:"id"`

	Domain   string `json:"domain" form:"domain"`
	Port     int    `json:"port" form:"port"`
	VisitLog string `json:"visit_log" form:"visit_log"`
	Status   string `json:"status" form:"status"`
}
type WafSslExpireDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafSslExpireDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafSslExpireSearchReq struct {
	Domain string `json:"domain" form:"domain"`
	request.PageInfo
}
