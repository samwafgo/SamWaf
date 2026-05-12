package model

import "SamWaf/model/baseorm"

/*
负载均衡模型
*/
type LoadBalance struct {
	baseorm.BaseOrm
	HostCode    string `gorm:"size:64" json:"host_code"` //网站唯一码（主要键）
	Remote_port int    `json:"remote_port"`              //远端端口
	Remote_ip   string `gorm:"size:64" json:"remote_ip"` //远端指定IP
	Weight      int    `json:"weight"`                   //权重
	Remarks     string `gorm:"size:500" json:"remarks"`  //备注
}
