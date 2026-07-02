package model

import (
	"SamWaf/customtype"
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
	CertContent string              `gorm:"type:text" json:"cert_content"` // 证书文件内容
	KeyContent  string              `gorm:"type:text" json:"key_content"`  // 密钥文件内容
	SerialNo    string              `gorm:"size:255" json:"serial_no"`     // 证书序列号
	Subject     string              `gorm:"size:500" json:"subject"`       // 证书主题
	Issuer      string              `gorm:"size:500" json:"issuer"`        // 颁发者
	ValidFrom   customtype.JsonTime `json:"valid_from"`                    // 证书有效期开始时间(未解析时为NULL，避免MySQL严格模式拒绝0000-00-00)
	ValidTo     customtype.JsonTime `json:"valid_to"`                      // 证书有效期结束时间(未解析时为NULL，避免MySQL严格模式拒绝0000-00-00)
	Domains     string              `gorm:"type:text" json:"domains"`      // 证书适用的域名
	KeyPath     string              `gorm:"size:500" json:"key_path"`      //密钥文件位置
	CertPath    string              `gorm:"size:500" json:"cert_path"`     //crt文件配置
	// 是否启用「凌晨3点从上面路径自动加载证书」：1=开启(默认) 0=关闭。
	// 当该证书夹由 SamWaf 自动申请管理时会被自动置为0，避免两个自动渠道互相覆盖。
	AutoLoadPath int `gorm:"default:1" json:"auto_load_path"`
}

// ExpirationMessage 获取到期提示信息
func (s *SslConfig) ExpirationMessage() string {
	now := time.Now()
	daysLeft := time.Time(s.ValidTo).Sub(now).Hours() / 24

	if daysLeft > 0 {
		return fmt.Sprintf("还有 %.0f 天到期", daysLeft)
	} else {
		return fmt.Sprintf("已过期 %.0f 天", -daysLeft)
	}
}

// CertFileLoadDiag 路径自动加载的诊断信息，供调用方（SSLReload）记录日志使用。
// 不在 model 层打日志，只把现场信息回传给调用方，由调用方决定日志级别与措辞。
type CertFileLoadDiag struct {
	CertPath    string    // crt 文件路径
	KeyPath     string    // key 文件路径
	CertExists  bool      // crt 文件是否存在
	KeyExists   bool      // key 文件是否存在
	CertModTime time.Time // crt 文件最后修改时间
	KeyModTime  time.Time // key 文件最后修改时间
	OldSerial   string    // 现有(库内)证书序列号
	OldValidTo  time.Time // 现有(库内)证书到期时间
	NewSerial   string    // 路径文件解析出的证书序列号（解析失败时为空）
	NewValidTo  time.Time // 路径文件解析出的证书到期时间
	// SkipLevel 当返回 error(即跳过本条目)时，建议调用方使用的日志级别：
	// "info"=正常跳过(证书相同/现有更新), "warn"=数据问题(文件缺失/解析失败/已过期), "error"=异常
	SkipLevel string
}

// 检查信息并进行赋值
func (s *SslConfig) CheckKeyAndCertFileLoad() (error, SslConfig, SslConfig, CertFileLoadDiag) {
	diag := CertFileLoadDiag{
		CertPath:   s.CertPath,
		KeyPath:    s.KeyPath,
		OldSerial:  s.SerialNo,
		OldValidTo: time.Time(s.ValidTo),
		SkipLevel:  "warn",
	}

	// 检查 key 文件是否存在
	if keyInfo, err := os.Stat(s.KeyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("密钥文件不存在: %s", s.KeyPath), SslConfig{}, SslConfig{}, diag
		}
		return fmt.Errorf("密钥文件不可访问: %s, %v", s.KeyPath, err), SslConfig{}, SslConfig{}, diag
	} else {
		diag.KeyExists = true
		diag.KeyModTime = keyInfo.ModTime()
	}

	// 检查 cert 文件是否存在
	if certInfo, err := os.Stat(s.CertPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("证书文件不存在: %s", s.CertPath), SslConfig{}, SslConfig{}, diag
		}
		return fmt.Errorf("证书文件不可访问: %s, %v", s.CertPath, err), SslConfig{}, SslConfig{}, diag
	} else {
		diag.CertExists = true
		diag.CertModTime = certInfo.ModTime()
	}

	// 读取密钥文件内容
	keyContent, err := ioutil.ReadFile(s.KeyPath)
	if err != nil {
		return fmt.Errorf("无法读取密钥文件: %v", err), SslConfig{}, SslConfig{}, diag
	}

	// 读取证书文件内容
	certContent, err := ioutil.ReadFile(s.CertPath)
	if err != nil {
		return fmt.Errorf("无法读取证书文件: %v", err), SslConfig{}, SslConfig{}, diag
	}

	block, _ := pem.Decode([]byte(certContent))
	if block == nil {
		return errors.New("无法解码PEM数据"), SslConfig{}, SslConfig{}, diag
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("解析证书失败"), SslConfig{}, SslConfig{}, diag
	}

	serialNo := cert.SerialNumber.String()
	diag.NewSerial = serialNo
	diag.NewValidTo = cert.NotAfter

	if serialNo == s.SerialNo {
		// 正常情况：路径文件与库内证书相同，无需更新
		diag.SkipLevel = "info"
		return errors.New("证书相同直接忽略"), SslConfig{}, SslConfig{}, diag
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
		return errors.New("路径下的文件已经过期，不加载"), SslConfig{}, SslConfig{}, diag
	}
	//现有证书大于路径下的也不进行更新
	if time.Time(s.ValidTo).After(validTo) {
		// 正常情况：库内证书比路径文件更新
		diag.SkipLevel = "info"
		return errors.New("现有证书到期时间大于路径下的到期时间也不进行更新"), SslConfig{}, SslConfig{}, diag
	}

	updateSslConfig := *s
	backSslConfig := *s

	updateSslConfig.KeyContent = string(keyContent)
	updateSslConfig.CertContent = string(certContent)
	updateSslConfig.SerialNo = serialNo
	updateSslConfig.Subject = subject
	updateSslConfig.Issuer = issuer
	updateSslConfig.Domains = domains
	updateSslConfig.ValidFrom = customtype.JsonTime(validFrom)
	updateSslConfig.ValidTo = customtype.JsonTime(validTo)

	return nil, updateSslConfig, backSslConfig, diag
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
	s.ValidFrom = customtype.JsonTime(validFrom)
	s.ValidTo = customtype.JsonTime(validTo)
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
	daysLeft := time.Time(current.ValidTo).Sub(now).Hours() / 24
	//如果当前证书已经到期了 则不更新
	if daysLeft <= 0 {
		ret = false
	}
	return ret
}
