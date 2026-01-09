package model

import "SamWaf/model/baseorm"

// BlockingPage 自定义拦截模板界面
type BlockingPage struct {
	baseorm.BaseOrm
	BlockingPageName string `json:"blocking_page_name"` //自定义拦截模板页面名称
	BlockingType     string `json:"blocking_type"`      //自定义类型 被拦截
	AttackType       string `json:"attack_type"`        //攻击类型 如: cc_attack, sensitive_word, sql_injection等
	HostCode         string `json:"host_code"`          //适用于某个网站唯一码
	ResponseCode     string `json:"response_code"`      //响应代码 默认403
	ResponseHeader   string `json:"response_header"`    //响应Header头信息（JSON）
	ResponseContent  string `json:"response_content"`   //响应内容
}
