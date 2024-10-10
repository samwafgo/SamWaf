package model

import (
	"SamWaf/model/baseorm"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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

// 获取到期提示信息
func (s *SslConfig) ExpirationMessage() string {
	now := time.Now()
	daysLeft := s.ValidTo.Sub(now).Hours() / 24

	if daysLeft > 0 {
		return fmt.Sprintf("还有 %.0f 天到期", daysLeft)
	} else {
		return fmt.Sprintf("已过期 %.0f 天", -daysLeft)
	}
}

// 检查信息并进行赋值
func (s *SslConfig) CheckKeyAndCertFileLoad(currentPath string) (error, SslConfig, SslConfig) {
	keyFilePath := filepath.Join(currentPath, "ssl", s.Id, "domain.key")
	certFilePath := filepath.Join(currentPath, "ssl", s.Id, "domain.crt")
	// 检查 key 文件是否存在
	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("密钥文件不存在: %s", keyFilePath), SslConfig{}, SslConfig{}
	}

	// 检查 cert 文件是否存在
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		return fmt.Errorf("证书文件不存在: %s", certFilePath), SslConfig{}, SslConfig{}
	}

	// 读取密钥文件内容
	keyContent, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("无法读取密钥文件: %v", err), SslConfig{}, SslConfig{}
	}

	// 读取证书文件内容
	certContent, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return fmt.Errorf("无法读取证书文件: %v", err), SslConfig{}, SslConfig{}
	}

	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return errors.New("无法解码PEM数据"), SslConfig{}, SslConfig{}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("解析证书失败"), SslConfig{}, SslConfig{}
	}

	serialNo := cert.SerialNumber.String()

	if serialNo == s.SerialNo {
		return errors.New("证书相同直接忽略"), SslConfig{}, SslConfig{}
	}

	subject := cert.Subject.String()
	issuer := cert.Issuer.String()
	validFrom := cert.NotBefore
	validTo := cert.NotAfter

	domains := ""
	if len(cert.DNSNames) > 0 {
		for _, domain := range cert.DNSNames {
			if domains != "" {
				domains += ", "
			}
			domains += domain
		}
	} else {
		domains = "未指定域名"
	}

	now := time.Now()
	daysLeft := validTo.Sub(now).Hours() / 24
	if daysLeft <= 0 {
		return errors.New("路径下的文件已经过期，不加载"), SslConfig{}, SslConfig{}
	}
	updateSslConfig := *s
	backSslConfig := *s

	updateSslConfig.KeyContent = string(keyContent)
	updateSslConfig.CertContent = string(certContent)
	updateSslConfig.SerialNo = serialNo
	updateSslConfig.Subject = subject
	updateSslConfig.Issuer = issuer
	updateSslConfig.Domains = domains
	updateSslConfig.ValidFrom = validFrom
	updateSslConfig.ValidTo = validTo

	return nil, updateSslConfig, backSslConfig
}
