package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PrintSSLCert 打印证书信息
func PrintSSLCert(cert string) string {
	result := ""
	block, _ := pem.Decode([]byte(cert))
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
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
			} else {
				domains = "未指定域名"
			}
			result = fmt.Sprintf("serialNo=%s  subject=%s  issuer=%s validFrom=%v  validTo=%v  domains=%s", serialNo, subject, issuer, validFrom, validTo, domains)

		} else {
			result = "格式错误2"
		}
	} else {
		result = "格式错误"
	}
	return result
}
