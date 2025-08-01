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

// WafSensitiveBatchDelReq 批量删除敏感词请求
type WafSensitiveBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` //敏感词唯一键数组
}

// WafSensitiveDelAllReq 删除所有敏感词请求
type WafSensitiveDelAllReq struct {
	// 可以添加一些过滤条件，比如按检测方向删除
	CheckDirection string `json:"check_direction"` //可选：按检测方向删除 in,out,all
}
