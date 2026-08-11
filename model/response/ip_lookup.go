package response

// IPLookupHit 一条命中记录：这个 IP 出现在了哪个名单/封禁源里。
type IPLookupHit struct {
	Source     string `json:"source"`      // 来源码：ip_black/ip_white/ip_group/threat_ip/ip_failure/cc_ban/firewall/cdn
	SourceName string `json:"source_name"` // 来源显示名
	Scope      string `json:"scope"`       // 归属范围：网站名/组名/渠道名/厂商名；全局的写「全局」
	Matched    string `json:"matched"`     // 实际命中的那条规则原文(单IP/CIDR/通配符/区间)，缓存类无规则则为空
	Effect     string `json:"effect"`      // 命中后的效果：block/allow/none
	Detail     string `json:"detail"`      // 备注、剩余时间等补充说明

	// SystemLayer 标记这条拦截是否落在系统防火墙层。
	// 系统层是内核直接丢包，WAF 的 IP 白名单根本轮不到判定——前端要靠这个标记
	// 提醒用户「加白也不会通」，所以必须是结构化字段，不能让前端去解析 Detail 文案。
	SystemLayer bool `json:"system_layer"`
}

// IPLookupResp IP 归属查询结果。
// hits 为空表示这个 IP 目前不在任何名单里。
type IPLookupResp struct {
	IP string `json:"ip"`
	// QueryNote 输入被归一化时的说明(如输入网段、按其中某个IP查)。空=输入本来就是单个IP。
	QueryNote string        `json:"query_note"`
	Location  string        `json:"location"` // 归属地，查不到为空
	Hits      []IPLookupHit `json:"hits"`
	Sources   []string      `json:"sources"`  // 本次实际查了哪些源，便于前端说明覆盖范围
	Degraded  []string      `json:"degraded"` // 查询过程中失败/跳过的源(如快照解压失败)，避免把「查不到」误报成「不在名单里」
}
