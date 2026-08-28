package request

import "SamWaf/model/common/request"

// ---------- 网站分组 ----------

// 分组短码由后端自动生成，不接受前端传入：它只是内部引用键，
// 让用户自定义既没有收益，还多一处唯一性冲突要处理。
type WafHostGroupAddReq struct {
	GroupName string `json:"group_name" binding:"required"` //分组名称
	Color     string `json:"color"`                         //标签色，须命中 model.HostGroupColors
	Remarks   string `json:"remarks"`                       //备注
}

type WafHostGroupEditReq struct {
	Id        string `json:"id" binding:"required"`
	GroupName string `json:"group_name" binding:"required"` //只允许改名称/颜色/备注，分组短码不可变（网站在引用它）
	Color     string `json:"color"`
	Remarks   string `json:"remarks"`
}

// WafHostGroupDelReq 删除分组。
// 组内网站不会被删除，只把它们的 group_code 清空回落「未分组」，
// 因此不需要 force 这类二次确认参数。
type WafHostGroupDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafHostGroupDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafHostGroupSearchReq struct {
	GroupName string `json:"group_name"`
	request.PageInfo
}

// WafHostGroupSortReq 一次提交完整的分组 id 顺序，按数组下标写 sort_no。
// 提交全量而不是「把 A 挪到 B 前面」，是为了让前端的上移/下移与将来的拖拽共用一个接口。
type WafHostGroupSortReq struct {
	Ids []string `json:"ids" binding:"required"`
}

// WafHostGroupAssignReq 批量把网站指派到某个分组。
// GroupCode 为空 = 移出分组（回落未分组）。
type WafHostGroupAssignReq struct {
	HostCodes []string `json:"host_codes" binding:"required"`
	GroupCode string   `json:"group_code"`
}
