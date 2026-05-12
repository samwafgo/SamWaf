package model

import (
	"SamWaf/model/baseorm"
)

// Tunnel 隧道
type Tunnel struct {
	baseorm.BaseOrm
	Code              string `gorm:"size:64" json:"code"`                 //唯一码
	Name              string `gorm:"size:255" json:"name"`                //名称
	Port              string `gorm:"size:50" json:"port"`                 //端口可以多个,号隔开
	Protocol          string `gorm:"size:20" json:"protocol"`             //协议 tcp,udp
	RemotePort        int    `json:"remote_port"`                         //远端端口
	RemoteIp          string `gorm:"size:64" json:"remote_ip"`            //远端指定IP
	AllowIp           string `gorm:"type:text" json:"allow_ip"`           //允许访问的IP ,号隔开
	DenyIp            string `gorm:"type:text" json:"deny_ip"`            //拒绝访问的IP ,号隔开
	StartStatus       int    `json:"start_status"`                        //启动状态 如果是1 启动  ; 如果是0 不启动
	ConnTimeout       int    `json:"conn_timeout"`                        // 连接超时时间，单位秒 60s
	ReadTimeout       int    `json:"read_timeout"`                        // 读取超时时间，单位秒 0 表示不限制
	WriteTimeout      int    `json:"write_timeout"`                       // 写入超时时间，单位秒  0 表示不限制
	MaxInConnect      int    `json:"max_in_connect"`                      // 最大入站连接数 0 表示不限制
	MaxOutConnect     int    `json:"max_out_connect"`                     // 最大出站连接数 0 表示不限制
	AllowedTimeRanges string `gorm:"size:255" json:"allowed_time_ranges"` // 允许访问的时间段 格式: 08:00-10:00;11:00-12:00 空表示24小时可访问
	IpVersion         string `gorm:"size:20" json:"ip_version"`           // IP版本支持: "ipv4" 仅IPv4, "ipv6" 仅IPv6, "both" 同时支持IPv4和IPv6, 默认为"both"
	Remark            string `gorm:"size:500" json:"remark"`              //备注
	SSLStatus         int    `json:"ssl_status"`                          // SSL开关 0关闭 1开启
	SSLCertificate    string `gorm:"size:500" json:"ssl_certificate"`     // SSL证书路径
	SSLCertificateKey string `gorm:"size:500" json:"ssl_certificate_key"` // SSL密钥路径
	SSLProtocols      string `gorm:"size:100" json:"ssl_protocols"`       // SSL协议版本 如 TLSv1.2 TLSv1.3
}
