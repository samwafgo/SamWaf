package request

import "SamWaf/model/common/request"

type WafLoginHistorySearchReq struct {
	LoginAccount string `json:"login_account" form:"login_account"` //登录账号
	LoginIp      string `json:"login_ip" form:"login_ip"`           //登录IP
	IsChanged    string `json:"is_changed" form:"is_changed"`       //是否与上次不一致 ""不过滤 "0"未变化 "1"变化
	request.PageInfo
}
