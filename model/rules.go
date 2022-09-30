package model

type Rules struct {
	Id              int    `gorm:"primary_key" json:" - "` //
	Tenant_id       string `json:"tenant_id"`              //
	Code            string `json:"code"`                   //
	Rulename        string `json:"rulename"`               //规则名称
	Rulecontent     string `json:"rulecontent"`            //规则内容
	Ruleversionname string `json:"ruleversionname"`        //规则版本名
	Ruleversion     int    `json:"ruleversion"`            //规则版本号
	User_code       string `json:"user_code"`              //用户编码
}
