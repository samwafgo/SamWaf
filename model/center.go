package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

/*
*
管控中心保存
*/
type Center struct {
	baseorm.BaseOrm
	ClientServerName     string              `gorm:"size:255" json:"client_server_name"`       // 客户端-自定义名称
	ClientUserCode       string              `gorm:"size:64" json:"client_user_code"`          // 客户端-用户码
	ClientTenantId       string              `gorm:"size:64" json:"client_tenant_id"`          // 客户端-租户ID
	ClientToken          string              `gorm:"size:500" json:"client_token"`             // 客户端-访问密钥
	ClientSsl            string              `gorm:"size:10" json:"client_ssl"`                // 客户端-是否https
	ClientIP             string              `gorm:"size:64" json:"client_ip"`                 //客户端 ip
	ClientPort           string              `gorm:"size:10" json:"client_port"`               //客户端 port
	ClientNewVersion     string              `gorm:"size:64" json:"client_new_version"`        //客户端 版本号
	ClientNewVersionDesc string              `gorm:"type:text" json:"client_new_version_desc"` //客户端 版本描述
	ClientSystemType     string              `gorm:"size:50" json:"client_system_type"`        //操作系统类型
	LastVisitTime        customtype.JsonTime `json:"last_visit_time"`                          //上次访问时间
	Remarks              string              `gorm:"size:500" json:"remarks"`                  //备注
}
