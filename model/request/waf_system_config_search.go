package request

import "SamWaf/model/common/request"

type WafSystemConfigSearchReq struct {
	Item    string `json:"item" form:"item"`
	Remarks string `json:"remarks" form:"remarks"`
	request.PageInfo
}
