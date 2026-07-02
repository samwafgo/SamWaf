package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
	"errors"
	"fmt"
	"time"
)

// SslOrder 证书申请
type SslOrder struct {
	baseorm.BaseOrm
	HostCode                string              `gorm:"size:64" json:"host_code"`               //网站唯一码（主要键）
	ApplyPlatform           string              `gorm:"size:100" json:"apply_platform"`         //申请平台
	ApplyMethod             string              `gorm:"size:50" json:"apply_method"`            //申请方式http01，dns
	SkipDNSVerify           int64               `json:"skip_dns_verify"`                        //dns01是否跳过本地DNS传播校验 0否 1是
	ApplyDns                string              `gorm:"size:100" json:"apply_dns"`              //申请dns服务商
	ApplyEmail              string              `gorm:"size:255" json:"apply_email"`            //申请邮箱
	ApplyKey                string              `gorm:"size:255" json:"apply_key"`              //申请私钥
	ApplyDomain             string              `gorm:"size:255" json:"apply_domain"`           //申请域名
	ApplyStatus             string              `gorm:"size:50" json:"apply_status"`            //申请状态 提交,完成,已续签
	ResultError             string              `gorm:"type:text" json:"result_error"`          //申请错误的详情
	ResultDomain            string              `gorm:"size:255" json:"result_domain"`          //返回结果信息
	ResultCertURL           string              `gorm:"size:500" json:"result_cert_url"`        //证书连接位置
	ResultCertStableURL     string              `gorm:"size:500" json:"result_cert_stable_url"` //证书固定连接位置
	ResultPrivateKey        []byte              `json:"result_private_key"`                     //证书私钥信息
	ResultCertificate       []byte              `json:"result_certificate"`                     //证书信息
	ResultIssuerCertificate []byte              `json:"result_issuer_certificate"`              //证书所属信息
	ResultValidTo           customtype.JsonTime `json:"result_valid_to"`                        //证书有效期结束时间(未获取到证书时为NULL，避免MySQL严格模式拒绝0000-00-00)
	ResultCSR               []byte              `json:"result_csr"`                             //csr信息
	Remarks                 string              `gorm:"size:500" json:"remarks"`                //备注信息
	PrivateGroupName        string              `gorm:"size:255" json:"private_group_name"`     //密钥分组名称DNS有效
}

// ExpirationMessage 获取到期提示信息
func (s *SslOrder) ExpirationMessage() (bool, int, string, error) {
	if s.ResultCertificate == nil {
		return false, 0, "", errors.New("未获取到期时间")
	}
	now := time.Now()
	daysLeft := time.Time(s.ResultValidTo).Sub(now).Hours() / 24

	if daysLeft > 0 {
		return false, int(daysLeft), fmt.Sprintf("还有 %.0f 天到期", daysLeft), nil
	} else {
		return true, int(daysLeft), fmt.Sprintf("已过期 %.0f 天", -daysLeft), nil
	}
}
