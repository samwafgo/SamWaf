package request

import "SamWaf/model/common/request"

type WafSystemConfigSearchReq struct {
	Item string `json:"item" form:"item"`
	request.PageInfo
}
