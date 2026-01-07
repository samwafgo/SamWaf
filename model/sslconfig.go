package model

import (
	"SamWaf/model/baseorm"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
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
	KeyPath     string    `json:"key_path"`     //密钥文件位置
	CertPath    string    `json:"cert_path"`    //crt文件配置
}

// ExpirationMessage 获取到期提示信息
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
func (s *SslConfig) CheckKeyAndCertFileLoad() (error, SslConfig, SslConfig) {

	// 检查 key 文件是否存在
	if _, err := os.Stat(s.KeyPath); os.IsNotExist(err) {
		return fmt.Errorf("密钥文件不存在: %s", s.KeyPath), SslConfig{}, SslConfig{}
	}

	// 检查 cert 文件是否存在
	if _, err := os.Stat(s.CertPath); os.IsNotExist(err) {
		return fmt.Errorf("证书文件不存在: %s", s.CertPath), SslConfig{}, SslConfig{}
	}

	// 读取密钥文件内容
	keyContent, err := ioutil.ReadFile(s.KeyPath)
	if err != nil {
		return fmt.Errorf("无法读取密钥文件: %v", err), SslConfig{}, SslConfig{}
	}

	// 读取证书文件内容
	certContent, err := ioutil.ReadFile(s.CertPath)
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
	}
	// 检查是否有IP地址
	if len(cert.IPAddresses) > 0 {
		for _, ip := range cert.IPAddresses {
			if domains != "" {
				domains += ", "
			}
			domains += ip.String()
		}
	}
	// 如果既没有域名也没有IP
	if domains == "" {
		domains = "未指定域名或IP"
	}

	now := time.Now()
	daysLeft := validTo.Sub(now).Hours() / 24
	if daysLeft <= 0 {
		return errors.New("路径下的文件已经过期，不加载"), SslConfig{}, SslConfig{}
	}
	//现有证书大于路径下的也不进行更新
	if s.ValidTo.After(validTo) {
		return errors.New("现有证书到期时间大于路径下的到期时间也不进行更新"), SslConfig{}, SslConfig{}
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

// FillByCertAndKey 通过证书和密钥填写证书夹内容
func (s *SslConfig) FillByCertAndKey(certContent, keyContent string) error {

	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return errors.New("无法解码PEM数据")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("解析证书失败")
	}
	serialNo := cert.SerialNumber.String()

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
	}
	// 检查是否有IP地址
	if len(cert.IPAddresses) > 0 {
		for _, ip := range cert.IPAddresses {
			if domains != "" {
				domains += ", "
			}
			domains += ip.String()
		}
	}
	// 如果既没有域名也没有IP
	if domains == "" {
		domains = "未指定域名或IP"
	}
	s.KeyContent = keyContent
	s.CertContent = certContent
	s.SerialNo = serialNo
	s.Subject = subject
	s.Issuer = issuer
	s.Domains = domains
	s.ValidFrom = validFrom
	s.ValidTo = validTo
	return nil
}

// CompareSSLNeedUpdate 比较ssl证书是否能检测
func (s *SslConfig) CompareSSLNeedUpdate(current SslConfig, old SslConfig) bool {
	ret := true
	//如果证书编码相同 则不更
	if current.SerialNo == old.SerialNo {
		ret = false
	}
	now := time.Now()
	daysLeft := current.ValidTo.Sub(now).Hours() / 24
	//如果当前证书已经到期了 则不更新
	if daysLeft <= 0 {
		ret = false
	}
	return ret
}
