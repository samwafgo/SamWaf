package wafenginecore

import (
	"SamWaf/common/zlog"
	"crypto/tls"
	"errors"
	"strings"
	"sync"
)

type AllCertificate struct {
	Mux sync.Mutex
	Map map[string]*tls.Certificate
}

// LoadSSL 加载证书
func (ac *AllCertificate) LoadSSL(domain string, cert string, key string) error {
	ac.Mux.Lock()
	defer ac.Mux.Unlock()
	domain = strings.ToLower(domain)
	// 加载新的证书
	newCert, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return err
	}
	certificate, ok := ac.Map[domain]
	if !ok {
		ac.Map[domain] = &newCert
		return nil
	} else {
		if certificate == nil {
			ac.Map[domain] = &newCert
			return nil
		}
		if certificate != nil && certificate.Certificate[0] != nil {
			zlog.Debug("需要重新加载证书")
			ac.Map[domain] = &newCert
		}
	}

	// 检查域名是否已存在，如果存在则替换
	ac.Map[domain] = &newCert
	return nil
}

// LoadSSLByFilePath 加载证书从文件
func (ac *AllCertificate) LoadSSLByFilePath(domain string, certPath string, keyPath string) error {
	ac.Mux.Lock()
	defer ac.Mux.Unlock()
	domain = strings.ToLower(domain)
	// 加载新的证书
	newCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	certificate, ok := ac.Map[domain]
	if !ok {
		ac.Map[domain] = &newCert
		return nil
	} else {
		if certificate != nil && certificate.Certificate[0] != nil {
			zlog.Debug("需要重新加载证书")
			ac.Map[domain] = &newCert
		}
	}

	// 检查域名是否已存在，如果存在则替换
	ac.Map[domain] = &newCert
	return nil
}

// RemoveSSL 移除证书
func (ac *AllCertificate) RemoveSSL(domain string) error {
	ac.Mux.Lock()
	defer ac.Mux.Unlock()
	domain = strings.ToLower(domain)
	_, ok := ac.Map[domain]
	if ok {
		ac.Map[domain] = nil
	}
	return nil
}

// GetSSL 加载证书
func (ac *AllCertificate) GetSSL(domain string) *tls.Certificate {
	ac.Mux.Lock()
	defer ac.Mux.Unlock()
	domain = strings.ToLower(domain)
	certificate, ok := ac.Map[domain]
	if ok {
		return certificate
	}
	return nil
}

// GetCertificateFunc 获取证书的函数
func (waf *WafEngine) GetCertificateFunc(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	zlog.Debug("GetCertificate ", clientInfo.ServerName)
	x509Cert := waf.AllCertificate.GetSSL(clientInfo.ServerName)
	if x509Cert != nil {
		return x509Cert, nil
	}
	return nil, errors.New("config error")
}
