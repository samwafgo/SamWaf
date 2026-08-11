package request

// WafIPLookupReq IP 归属查询请求
type WafIPLookupReq struct {
	Ip string `json:"ip" form:"ip"` // 待查的 IPv4/IPv6 地址
	// Sources 只查指定来源(逗号分隔)，留空=全部。
	// 前端按来源分批请求，好让慢的那批(威胁情报)不挡住快的先出结果。
	Sources string `json:"sources" form:"sources"`
}
