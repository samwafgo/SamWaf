package model

import (
	"SamWaf/model/baseorm"
)

// Tunnel 隧道
type Tunnel struct {
	baseorm.BaseOrm
	Code          string `json:"code"`            //唯一码
	Name          string `json:"name"`            //名称
	Port          string `json:"port"`            //端口可以多个,号隔开
	Protocol      string `json:"protocol"`        //协议 tcp,udp
	RemotePort    int    `json:"remote_port"`     //远端端口
	RemoteIp      string `json:"remote_ip"`       //远端指定IP
	AllowIp       string `json:"allow_ip"`        //允许访问的IP ,号隔开
	DenyIp        string `json:"deny_ip"`         //拒绝访问的IP ,号隔开
	StartStatus   int    `json:"start_status"`    //启动状态 如果是1 启动  ; 如果是0 不启动
	ConnTimeout   int    `json:"conn_timeout"`    // 连接超时时间，单位秒 60s
	ReadTimeout   int    `json:"read_timeout"`    // 读取超时时间，单位秒 0 表示不限制
	WriteTimeout  int    `json:"write_timeout"`   // 写入超时时间，单位秒  0 表示不限制
	MaxInConnect  int    `json:"max_in_connect"`  // 最大入站连接数 0 表示不限制
	MaxOutConnect int    `json:"max_out_connect"` // 最大出站连接数 0 表示不限制
	Remark        string `json:"remark"`          //备注
}
