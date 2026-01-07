package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
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
			result = fmt.Sprintf("serialNo=%s  subject=%s  issuer=%s validFrom=%v  validTo=%v  domains=%s", serialNo, subject, issuer, validFrom, validTo, domains)

		} else {
			result = "格式错误2"
		}
	} else {
		result = "格式错误"
	}
	return result
}

// TLSVersionMap maps string representations to tls version constants
var TLSVersionMap = map[string]uint16{
	"SSLv3":   tls.VersionSSL30, //这个已经废弃了
	"TLS 1.0": tls.VersionTLS10,
	"TLS 1.1": tls.VersionTLS11,
	"TLS 1.2": tls.VersionTLS12,
	"TLS 1.3": tls.VersionTLS13,
}

// ParseTLSVersion parses string like "TLS 1.2" into uint16 version constant
func ParseTLSVersion(ver string) uint16 {
	ver = strings.TrimSpace(ver)
	if v, ok := TLSVersionMap[ver]; ok {
		return v
	}
	return tls.VersionTLS12 // Default to TLS 1.2 if not found
}
