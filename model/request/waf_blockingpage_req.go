package request

import "SamWaf/model/common/request"

type WafBlockingPageAddReq struct {
	BlockingPageName string `json:"blocking_page_name" form:"blocking_page_name"`
	BlockingType     string `json:"blocking_type" form:"blocking_type"`
	AttackType       string `json:"attack_type" form:"attack_type"`
	HostCode         string `json:"host_code" form:"host_code"`
	ResponseCode     string `json:"response_code" form:"response_code"`
	ResponseHeader   string `json:"response_header" form:"response_header"`
	ResponseContent  string `json:"response_content" form:"response_content"`
}
type WafBlockingPageEditReq struct {
	Id               string `json:"id"`
	BlockingPageName string `json:"blocking_page_name" form:"blocking_page_name"`
	BlockingType     string `json:"blocking_type" form:"blocking_type"`
	AttackType       string `json:"attack_type" form:"attack_type"`
	HostCode         string `json:"host_code" form:"host_code"`
	ResponseCode     string `json:"response_code" form:"response_code"`
	ResponseHeader   string `json:"response_header" form:"response_header"`
	ResponseContent  string `json:"response_content" form:"response_content"`
}
type WafBlockingPageDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafBlockingPageDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafBlockingPageSearchReq struct {
	request.PageInfo
}
