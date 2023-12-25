package model

import "SamWaf/model/baseorm"

type Hosts struct {
	baseorm.BaseOrm
	Code          string `json:"code"`          //唯一码
	Host          string `json:"host"`          //域名
	Port          int    `json:"port"`          //端口
	Ssl           int    `json:"ssl"`           //是否是ssl
	GUARD_STATUS  int    `json:"guard_status"`  //防御状态
	REMOTE_SYSTEM string `json:"remote_system"` //是宝塔 phpstudy等
	REMOTE_APP    string `json:"remote_app"`    //是什么类型的应用
	Remote_host   string `json:"remote_host"`   //远端域名
	Remote_port   int    `json:"remote_port"`   //远端端口
	Remote_ip     string `json:"remote_ip"`     //远端指定IP
	Certfile      string `json:"certfile"`      //证书文件
	Keyfile       string `json:"keyfile"`       //密钥文件
	REMARKS       string `json:"remarks"`       //备注
	GLOBAL_HOST   int    `json:"global_host"`   //默认全局 1 全局 0非全局
}
