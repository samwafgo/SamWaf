package model

import "time"

/*
*
整体统计
*/
type StatsTotal struct {
	Id                 int       `gorm:"primary_key" json:" - "`
	UserCode           string    `json:"user_code"`            //用户码（主要键）
	TenantId           string    `json:"tenant_id"`            //租户ID
	AttackCount        int       `json:"attack_count"`         //攻击数量
	VisitCount         int       `json:"visit_count"`          //访问数量
	HistoryAttackCount int       `json:"history_attack_count"` //历史攻击数量
	HistoryVisitCount  int       `json:"history_visit_count"`  //历史访问数量
	UpdateTime         time.Time `json:"update_time"`          //更新时间
}

/*
*
按天统计和不同类型统计
*/
type StatsDay struct {
	Id             int       `gorm:"primary_key" json:" - "`
	UserCode       string    `json:"user_code"`        //用户码（主要键）
	TenantId       string    `json:"tenant_id"`        //租户ID（主要键）
	HostCode       string    `json:"host_code"`        //网站唯一码（主要键）
	Day            int       `json:"day"`              //年月日（主要键）
	Host           string    `json:"host"`             //域名
	Type           string    `json:"type"`             //类型 放行,阻止
	Count          int       `json:"count"`            //数量
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}