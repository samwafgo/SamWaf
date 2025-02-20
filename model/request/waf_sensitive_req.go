package request

import "SamWaf/model/common/request"

type WafSensitiveAddReq struct {
	CheckDirection string `json:"check_direction"`          //敏感词检测方向 in ,out ,all
	Action         string `json:"action"`                   //敏感词检测后动作 deny,replace
	Content        string `json:"content" form:"content"  ` //内容
	Remarks        string `json:"remarks" form:"remarks"  ` //备注
}
type WafSensitiveDelReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}
type WafSensitiveDetailReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}

type WafSensitiveEditReq struct {
	Id             string `json:"id"`
	CheckDirection string `json:"check_direction"`          //敏感词检测方向 in ,out ,all
	Action         string `json:"action"`                   //敏感词检测后动作 deny,replace
	Content        string `json:"content" form:"content"  ` //内容
	Remarks        string `json:"remarks" form:"remarks"  ` //备注
}
type WafSensitiveSearchReq struct {
	Content string `json:"content" form:"content"  ` //内容
	Remarks string `json:"remarks" form:"remarks"  ` //备注
	request.PageInfo
}
