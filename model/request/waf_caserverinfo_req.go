package request

import "SamWaf/model/common/request"

type WafCaServerInfoAddReq struct {
	CaServerName    string `json:"ca_server_name" form:"ca_server_name"`
	CaServerAddress string `json:"ca_server_address" form:"ca_server_address"`
	Remarks         string `json:"remarks" form:"remarks"`
}
type WafCaServerInfoEditReq struct {
	Id string `json:"id"`

	CaServerName    string `json:"ca_server_name" form:"ca_server_name"`
	CaServerAddress string `json:"ca_server_address" form:"ca_server_address"`
	Remarks         string `json:"remarks" form:"remarks"`
}
type WafCaServerInfoDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafCaServerInfoDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafCaServerInfoSearchReq struct {
	request.PageInfo
}
