package waftask

import (
	"SamWaf/service/waf_service"
)

var (
	wafSysLogService       = waf_service.WafSysLogServiceApp
	wafSystemConfigService = waf_service.WafSystemConfigServiceApp
	wafLogService          = waf_service.WafLogServiceApp
)

type LastCounter struct {
	UNIX_ADD_TIME int64 `json:"unix_add_time" gorm:"index"` //添加日期unix
}
type CountHostResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}
type CountIPResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Ip       string `json:"ip"`        //域名
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}
type CountCityResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Country  string `json:"country"`   //国家
	Province string `json:"province"`  //省份
	City     string `json:"city"`      //城市
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}

type CountIPRuleResult struct {
	Ip   string `json:"ip"`   //用户ip
	Rule string `json:"rule"` //规则
	Cnt  int64  `json:"cnt"`  //数量
}

/**
定时统计
*/

func TaskCounter() {

	//废弃使用新形式
	if 1 == 1 {
		return
	}
}
