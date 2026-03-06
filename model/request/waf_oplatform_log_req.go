package request

import "SamWaf/model/common/request"

type WafOPlatformLogDelReq struct {
	Id string `json:"id" form:"id"` //唯一键
}

type WafOPlatformLogDetailReq struct {
	Id string `json:"id" form:"id"` //唯一键
}

type WafOPlatformLogSearchReq struct {
	KeyName       string `json:"key_name" form:"key_name"`             //Key名称
	RequestPath   string `json:"request_path" form:"request_path"`     //请求路径
	ClientIP      string `json:"client_ip" form:"client_ip"`           //客户端IP
	RequestMethod string `json:"request_method" form:"request_method"` //请求方法
	request.PageInfo
}
