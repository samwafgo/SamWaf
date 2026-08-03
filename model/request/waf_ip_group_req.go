package request

import "SamWaf/model/common/request"

// ---------- IP 组 ----------

// 组短码由后端自动生成，不接受前端传入：它只是内部引用键，
// 让用户自定义既没有收益，还多一处唯一性冲突要处理。
type WafIPGroupAddReq struct {
	GroupName string `json:"group_name" binding:"required"` //组名称
	Remarks   string `json:"remarks"`                       //备注
}

type WafIPGroupEditReq struct {
	Id        string `json:"id" binding:"required"`
	GroupName string `json:"group_name" binding:"required"` //只允许改名称与备注，组短码不可变（规则/名单都在引用它）
	Remarks   string `json:"remarks"`
}

type WafIPGroupDelReq struct {
	Id string `json:"id" form:"id"`
	// Force 为 1 时级联删除引用该组的黑/白名单条目。
	// 默认 0：有引用时拒绝删除并返回引用明细，避免静默删掉白名单条目把运维自己挡在门外。
	Force int `json:"force" form:"force"`
}

type WafIPGroupDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafIPGroupSearchReq struct {
	GroupName string `json:"group_name"`
	GroupCode string `json:"group_code"`
	request.PageInfo
}

type WafIPGroupRefsReq struct {
	GroupCode string `json:"group_code" form:"group_code"`
}

type WafIPGroupValidateReq struct {
	Ip string `json:"ip" binding:"required"`
}

// ---------- IP 组内条目 ----------

type WafIPGroupItemAddReq struct {
	GroupCode string `json:"group_code" binding:"required"`
	Ip        string `json:"ip" binding:"required"` //单IP / CIDR / 通配符 / 区间
	Remarks   string `json:"remarks"`
}

type WafIPGroupItemEditReq struct {
	Id      string `json:"id" binding:"required"`
	Ip      string `json:"ip" binding:"required"`
	Remarks string `json:"remarks"`
}

type WafIPGroupItemDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafIPGroupItemDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafIPGroupItemSearchReq struct {
	GroupCode string `json:"group_code"`
	Ip        string `json:"ip"`
	request.PageInfo
}

type WafIPGroupItemBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"`
}

// WafIPGroupItemBatchAddReq 多行文本批量录入，每行一个 IP 模式（忽略空行与 # 开头的注释行）
type WafIPGroupItemBatchAddReq struct {
	GroupCode string `json:"group_code" binding:"required"`
	Content   string `json:"content" binding:"required"`
	Remarks   string `json:"remarks"`
}

type WafIPGroupItemDelAllReq struct {
	GroupCode string `json:"group_code" form:"group_code" binding:"required"`
}
