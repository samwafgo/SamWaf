package request

import "SamWaf/model/common/request"

type WafTaskAddReq struct {
	TaskName string `json:"task_name" form:"task_name"`
	TaskUnit string `json:"task_unit" form:"task_unit"`

	TaskValue  int    `json:"task_value" form:"task_value"`
	TaskAt     string `json:"task_at" form:"task_at"`
	TaskMethod string `json:"task_method" form:"task_method"`
}
type WafTaskEditReq struct {
	Id string `json:"id"`

	TaskName string `json:"task_name" form:"task_name"`
	TaskUnit string `json:"task_unit" form:"task_unit"`

	TaskValue  int    `json:"task_value" form:"task_value"`
	TaskAt     string `json:"task_at" form:"task_at"`
	TaskMethod string `json:"task_method" form:"task_method"`
}
type WafTaskDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafTaskDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafTaskSearchReq struct {
	request.PageInfo
}
