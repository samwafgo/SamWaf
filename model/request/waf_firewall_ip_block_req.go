package request

import "SamWaf/model/common/request"

// WafFirewallIPBlockAddReq 添加防火墙IP封禁请求
type WafFirewallIPBlockAddReq struct {
	HostCode   string `json:"host_code"`             // 网站唯一码（主要键）
	IP         string `json:"ip" binding:"required"` // 被封禁的IP地址
	Reason     string `json:"reason"`                // 封禁原因
	BlockType  string `json:"block_type"`            // 封禁类型：manual-手动封禁, auto-自动封禁, temp-临时封禁
	ExpireTime int64  `json:"expire_time"`           // 过期时间（时间戳，0表示永久）
	Remarks    string `json:"remarks"`               // 备注
}

// WafFirewallIPBlockEditReq 编辑防火墙IP封禁请求
type WafFirewallIPBlockEditReq struct {
	Id         string `json:"id" binding:"required"` // 唯一键
	HostCode   string `json:"host_code"`             // 网站唯一码（主要键）
	IP         string `json:"ip" binding:"required"` // 被封禁的IP地址
	Reason     string `json:"reason"`                // 封禁原因
	BlockType  string `json:"block_type"`            // 封禁类型
	Status     string `json:"status"`                // 状态
	ExpireTime int64  `json:"expire_time"`           // 过期时间（时间戳，0表示永久）
	Remarks    string `json:"remarks"`               // 备注
}

// WafFirewallIPBlockDelReq 删除防火墙IP封禁请求
type WafFirewallIPBlockDelReq struct {
	Id string `json:"id" form:"id" binding:"required"` // 唯一键
}

// WafFirewallIPBlockSearchReq 搜索防火墙IP封禁请求
type WafFirewallIPBlockSearchReq struct {
	HostCode  string `json:"host_code"`  // 主机码
	IP        string `json:"ip"`         // IP地址
	Reason    string `json:"reason"`     // 封禁原因
	BlockType string `json:"block_type"` // 封禁类型
	Status    string `json:"status"`     // 状态
	request.PageInfo
}

// WafFirewallIPBlockDetailReq 获取防火墙IP封禁详情请求
type WafFirewallIPBlockDetailReq struct {
	Id string `json:"id" form:"id" binding:"required"` // 唯一键
}

// WafFirewallIPBlockBatchDelReq 批量删除防火墙IP封禁请求
type WafFirewallIPBlockBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` // 唯一键数组
}

// WafFirewallIPBlockBatchAddReq 批量添加防火墙IP封禁请求
type WafFirewallIPBlockBatchAddReq struct {
	HostCode  string   `json:"host_code"`              // 网站唯一码
	IPs       []string `json:"ips" binding:"required"` // IP地址列表
	Reason    string   `json:"reason"`                 // 封禁原因
	BlockType string   `json:"block_type"`             // 封禁类型
	Remarks   string   `json:"remarks"`                // 备注
}

// WafFirewallIPBlockEnableReq 启用防火墙IP封禁请求
type WafFirewallIPBlockEnableReq struct {
	Id string `json:"id" binding:"required"` // 唯一键
}

// WafFirewallIPBlockDisableReq 禁用防火墙IP封禁请求
type WafFirewallIPBlockDisableReq struct {
	Id string `json:"id" binding:"required"` // 唯一键
}

// WafFirewallIPBlockSyncReq 同步防火墙规则请求
type WafFirewallIPBlockSyncReq struct {
	HostCode string `json:"host_code"` // 网站唯一码（可选，为空则同步所有）
}

// WafFirewallIPBlockClearExpiredReq 清理过期规则请求
type WafFirewallIPBlockClearExpiredReq struct {
}
