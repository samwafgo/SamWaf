package model

import (
	"time"
)

type Hosts struct {
	Id          int    `gorm:"primary_key" json:" - "` //
	Tenant_id   string `json:"tenant_id"`              //租户ID
	Code        string `json:"code"`                   //唯一码
	Host        string `json:"host"`                   //域名
	Port        int    `json:"port"`                   //端口
	Ssl         int    `json:"ssl"`                    //是否是ssl
	Remote_host string `json:"remote_host"`            //远端域名
	Remote_port int    `json:"remote_port"`            //远端端口

	CreatedAt time.Time `json:"CreatedAt"` //创建时间
	UpdatedAt time.Time `json:"UpdatedAt"` //更新时间
}
