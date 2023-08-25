package model

import "time"

type Rules struct {
	Id              int       `gorm:"primary_key" json:" - "` //
	TenantId        string    `json:"tenant_id"`              //
	HostCode        string    `json:"host_code"`              //主机唯一码
	RuleCode        string    `json:"rule_code"`              //规则的唯一码
	RuleName        string    `json:"rule_name"`              //规则名称
	RuleContent     string    `json:"rule_content"`           //规则内容
	RuleContentJSON string    `json:"rule_content_json"`      //规则JSON内容
	RuleVersionName string    `json:"rule_version_name"`      //规则版本名
	RuleVersion     int       `json:"rule_version"`           //规则版本号
	UserCode        string    `json:"user_code"`              //用户编码
	IsPublicRule    int       `json:"is_public_rule"`         //是否为公共规则
	IsManualRule    int       `json:"is_manual_rule"`         //是否为手工写规则  1：手工编写 0 ：UI界面形式
	RuleStatus      int       `json:"rule_status"`            //规则是否开启 1，开启 0，关闭不生效 999 删除
	CreateTime      time.Time `json:"create_time"`            //创建时间
	LastUpdateTime  time.Time `json:"last_update_time"`       //上次更新时间
}
