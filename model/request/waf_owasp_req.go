package request

// WafOwaspRulesListReq 规则列表查询参数。
type WafOwaspRulesListReq struct {
	File      string `form:"file"`
	Severity  string `form:"severity"`
	Paranoia  int    `form:"paranoia"`
	Keyword   string `form:"keyword"`
	Status    string `form:"status"` // disabled / modified / default / ""(全部)
	PageIndex int    `form:"page_index"`
	PageSize  int    `form:"page_size"`
}

// WafOwaspRuleToggleReq 启用/禁用请求。
type WafOwaspRuleToggleReq struct {
	ID         int    `json:"id" binding:"required"`
	Disabled   bool   `json:"disabled"`
	SourceFile string `json:"source_file"`
}

// WafOwaspRuleOverrideReq 改写规则请求。
type WafOwaspRuleOverrideReq struct {
	ID         int    `json:"id" binding:"required"`
	SourceFile string `json:"source_file"`
	Content    string `json:"content" binding:"required"`
}

// WafOwaspRuleResetReq 还原规则。
type WafOwaspRuleResetReq struct {
	ID int `json:"id" binding:"required"`
}

// WafOwaspCRSVarSetReq 设置单个 CRS 变量请求体。
type WafOwaspCRSVarSetReq struct {
	Key   string `json:"key" binding:"required"` // 变量名，可带或不带 tx. 前缀
	Value string `json:"value"`                  // 变量值（允许空字符串以清空值）
}

// WafOwaspDryRunReq 沙盒测试请求。
type WafOwaspDryRunReq struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
