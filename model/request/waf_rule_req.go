package request

import "SamWaf/model/common/request"

type WafRuleAddReq struct {
	RuleCode     string `json:"rule_code"` //规则编号v4
	RuleJson     string `json:"rule_json"`
	IsManualRule int    `json:"is_manual_rule"` // 0 是界面  1是纯代码
	RuleContent  string `json:"rule_content"`   //规则内容
	RuleStatus   int    `json:"rule_status"`    //规则状态 1 是开启 0 是关闭
}
type WafRuleDelReq struct {
	CODE string `json:"code" form:"code" binding:"required"`
}
type WafRuleDetailReq struct {
	CODE string `json:"code" form:"code" binding:"required"`
}
type WafRuleEditReq struct {
	CODE         string `json:"code"`
	RuleJson     string `json:"rule_json"`
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
	RuleStatus   int    `json:"rule_status"`  //规则状态 1 是开启 0 是关闭
}
type WafRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"` //主机码
	RuleName string `json:"rule_name" form:"rule_name"` //规则名
	RuleCode string `json:"rule_code" form:"rule_code"` //规则编号v4
	request.PageInfo
}
type WafRuleBatchDelReq struct {
	Codes []string `json:"codes" binding:"required"` //规则编码数组
}

type WafRuleDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}
type WafRulePreViewReq struct {
	RuleCode     string `json:"rule_code"`      //规则编号v4
	RuleJson     string `json:"rule_json"`      //规则json字符串
	IsManualRule int    `json:"is_manual_rule"` // 0 是界面  1是纯代码
	RuleContent  string `json:"rule_content"`   //规则内容
	FormSource   string `json:"form_source"`    //来源是 builder ？ 不校验 选择的站点
}

type WafRuleStatusReq struct {
	CODE        string `json:"code" form:"code" binding:"required"`
	RULE_STATUS int    `json:"rule_status" form:"rule_status"` //规则状态 1 是开启 0 是关闭
}

// WafRuleTestReq 规则测试请求
type WafRuleTestReq struct {
	RuleJson     string `json:"rule_json"`      // 规则JSON
	RuleContent  string `json:"rule_content"`   // 规则内容（手工模式）
	IsManualRule int    `json:"is_manual_rule"` // 是否手工模式
	RuleCode     string `json:"rule_code"`      // 规则代码
	// 模拟请求数据（与真实请求字段对应）
	TestSrcIP     string `json:"test_src_ip"`     // 模拟源IP（自动解析国家/省份/城市）
	TestHost      string `json:"test_host"`       // 模拟Host（如 example.com:80）
	TestURL       string `json:"test_url"`        // 模拟URL（如 /api/test?a=1）
	TestMethod    string `json:"test_method"`     // 模拟HTTP方法（GET/POST等）
	TestUserAgent string `json:"test_user_agent"` // 模拟User-Agent
	TestReferer   string `json:"test_referer"`    // 模拟Referer
	TestHeader    string `json:"test_header"`     // 模拟Header（key: value\r\n格式）
	TestCookies   string `json:"test_cookies"`    // 模拟Cookies
	TestBody      string `json:"test_body"`       // 模拟请求Body
}
