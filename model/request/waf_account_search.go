package request

import "SamWaf/model/common/request"

type WafAccountSearchReq struct {
	LoginAccount string `json:"login_account" form:"login_account"` //登录账号
	request.PageInfo
}
