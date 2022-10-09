package model

type Rules struct {
	Id              int    `gorm:"primary_key" json:" - "` //
	Tenant_id       string `json:"tenant_id"`              //
	Code            string `json:"code"`                   //
	Rule_Code       string `json:"rule_code"`              //规则的唯一码
	Rulename        string `json:"rulename"`               //规则名称
	Rulecontent     string `json:"rulecontent"`            //规则内容
	RulecontentJSON string `json:"rulecontent_json"`       //规则JSON内容
	Ruleversionname string `json:"ruleversionname"`        //规则版本名
	Ruleversion     int    `json:"ruleversion"`            //规则版本号
	User_code       string `json:"user_code"`              //用户编码
	IsPublicRule    int    `json:"is_public_rule"`         //是否为公共规则
	RuleStatus      string `json:"rule_status"`            //规则是否开启 1，开启 0，关闭不生效
}
