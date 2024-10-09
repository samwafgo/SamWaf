package model

import (
	"SamWaf/model/baseorm"
	"time"
)

type SslConfig struct {
	baseorm.BaseOrm
	CertContent string    `json:"cert_content"` // 证书文件内容
	KeyContent  string    `json:"key_content"`  // 密钥文件内容
	SerialNo    string    `json:"serial_no"`    // 证书序列号
	Subject     string    `json:"subject"`      // 证书主题
	Issuer      string    `json:"issuer"`       // 颁发者
	ValidFrom   time.Time `json:"valid_from"`   // 证书有效期开始时间
	ValidTo     time.Time `json:"valid_to"`     // 证书有效期结束时间
	Domains     string    `json:"domains"`      // 证书适用的域名
}
