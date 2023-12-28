package request

import "SamWaf/model/common/request"

type WafHostSearchReq struct {
	Code    string `json:"code" `   //主机码
	REMARKS string `json:"remarks"` //备注
	request.PageInfo
}
