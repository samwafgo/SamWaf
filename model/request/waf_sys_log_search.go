package request

import "SamWaf/model/common/request"

type WafSysLogSearchReq struct {
	OpType    string `json:"op_type" form:"op_type"`       //操作类型
	OpContent string `json:"op_content" form:"op_content"` //操作内容
	request.PageInfo
}
