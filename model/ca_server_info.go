package model

import "SamWaf/model/baseorm"

type CaServerInfo struct {
	baseorm.BaseOrm
	CaServerName    string `json:"ca_server_name"`    //CA服务器名称
	CaServerAddress string `json:"ca_server_address"` //CA服务器地址
	Remarks         string `json:"remarks"`           //备注
}
