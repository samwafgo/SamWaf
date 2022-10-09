package model

type Rules struct {
	Id              int    `gorm:"primary_key" json:" - "` //
	TenantId        string `json:"tenant_id"`              //
	HostCode        string `json:"host_code"`              //主机唯一码
	RuleCode        string `json:"rule_code"`              //规则的唯一码
	RuleName        string `json:"rule_name"`              //规则名称
	RuleContent     string `json:"rule_content"`           //规则内容
	RuleContentJSON string `json:"rule_content_json"`      //规则JSON内容
	RuleVersionName string `json:"rule_version_name"`      //规则版本名
	RuleVersion     int    `json:"rule_version"`           //规则版本号
	UserCode        string `json:"user_code"`              //用户编码
	IsPublicRule    int    `json:"is_public_rule"`         //是否为公共规则
	RuleStatus      string `json:"rule_status"`            //规则是否开启 1，开启 0，关闭不生效
}
