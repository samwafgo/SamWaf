package model

import (
	"SamWaf/model/baseorm"
)

/*
*
整体统计
*/
type StatsTotal struct {
	baseorm.BaseOrm
	AttackCount        int `json:"attack_count"`         //攻击数量
	VisitCount         int `json:"visit_count"`          //访问数量
	HistoryAttackCount int `json:"history_attack_count"` //历史攻击数量
	HistoryVisitCount  int `json:"history_visit_count"`  //历史访问数量
}

/*
*
按天统计和不同类型统计
*/
type StatsDay struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Type     string `json:"type"`      //类型 放行,阻止
	Count    int    `json:"count"`     //数量
}

/*
*
按天统计和不同类型统计IP
*/
type StatsIPDay struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	IP       string `json:"ip"`        //ip
	Type     string `json:"type"`      //类型 放行,阻止
	Count    int    `json:"count"`     //数量
}

/*
*
按天统计和不同类型统计城市
*/
type StatsIPCityDay struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Country  string `json:"country"`   //国家
	Province string `json:"province"`  //省份
	City     string `json:"city"`      //城市
	Type     string `json:"type"`      //类型 放行,阻止
	Count    int    `json:"count"`     //数量
}

/*
*
天数对应的数量[临时]
*/
type StatsDayCount struct {
	Day   int   `json:"day"`   //年月日
	Count int64 `json:"count"` //数量
}

/*
*
域名对应的数量[临时]
*/
type StatsIPCount struct {
	IP       string `json:"ip"`        //ip
	IPBelong string `json:"ip_belong"` //归属地
	Count    int64  `json:"count"`     //数量
}

/*
*
域名对应的数量丰富的标签内容
*/
type StatsIPCountMore struct {
	IP       string  `json:"ip"`        //ip
	IPBelong string  `json:"ip_belong"` //归属地
	IPTag    []IPTag `json:"ip_tags"`   //IP标签
	Count    int64   `json:"count"`     //数量
}
