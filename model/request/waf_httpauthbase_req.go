package request

import "SamWaf/model/common/request"

type WafHttpAuthBaseAddReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	UserName string `json:"user_name" form:"user_name"`
	Password string `json:"password" form:"password"`
}
type WafHttpAuthBaseEditReq struct {
	Id       string `json:"id"`
	HostCode string `json:"host_code" form:"host_code"`
	UserName string `json:"user_name" form:"user_name"`
	Password string `json:"password" form:"password"`
}
type WafHttpAuthBaseDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafHttpAuthBaseDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafHttpAuthBaseSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	UserName string `json:"user_name" form:"user_name"`
	request.PageInfo
}
