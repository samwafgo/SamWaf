package wafenginecore

import (
	"SamWaf/common/domaintool"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"crypto/tls"
	"errors"
	"net"
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
		delete(ac.Map, domain)
	}
	return nil
}

// GetSSL 加载证书 - 支持通配符域名匹配
func (ac *AllCertificate) GetSSL(domain string) *tls.Certificate {
	ac.Mux.Lock()
	defer ac.Mux.Unlock()
	domain = strings.ToLower(domain)

	// 首先尝试精确匹配
	certificate, ok := ac.Map[domain]
	if ok && certificate != nil {
		return certificate
	}

	// 如果精确匹配失败，尝试通配符匹配
	// 例如：ssl1.samwaf.com 匹配 *.samwaf.com
	domainParts := strings.Split(domain, ".")
	if len(domainParts) >= 2 {
		// 构造通配符域名，从最具体的开始匹配
		for i := 0; i < len(domainParts)-1; i++ {
			// 构造通配符域名
			wildcardDomain := "*." + strings.Join(domainParts[i+1:], ".")
			certificate, ok := ac.Map[wildcardDomain]
			if ok && certificate != nil {
				return certificate
			}
		}
	}

	return nil
}

// GetCertificateFunc 获取证书的函数
func (waf *WafEngine) GetCertificateFunc(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := clientInfo.ServerName
	// 如果 ServerName 为空（通常是 IP 访问），尝试从连接中获取服务器 IP
	if serverName == "" {
		if clientInfo.Conn != nil {
			// 获取服务器本地地址
			localAddr := clientInfo.Conn.LocalAddr().String()
			// 去掉端口号，只保留 IP
			if host, _, err := net.SplitHostPort(localAddr); err == nil {
				if global.GCONFIG_RECORD_SSL_IP_CERT_IP != "" {
					serverName = global.GCONFIG_RECORD_SSL_IP_CERT_IP
					zlog.Debug("Using configured real IP: ", serverName)
				} else if global.GWAF_RUNTIME_IP != "" {
					serverName = global.GWAF_RUNTIME_IP
					zlog.Debug("Using out real IP: ", serverName)
				} else {
					serverName = host
					zlog.Debug("Using local IP address: ", serverName)
				}
			}

		}

		// 如果还是空，返回错误
		if serverName == "" {
			zlog.Debug("No ServerName and unable to get local address")
			return nil, errors.New("no server name or IP address found")
		}
	}
	zlog.Debug("GetCertificate ", serverName)
	x509Cert := waf.AllCertificate.GetSSL(serverName)
	if x509Cert != nil {
		return x509Cert, nil
	}
	return nil, errors.New("certificate not found for domain: " + serverName)
}

// isHTTP2DisabledForServerName 按 SNI + 端口解析出站点，读其 DisableHTTP2。
// 解析逻辑镜像 ServeHTTP 的域名匹配（宽松端口/精确/泛域名/绑定多域名/通配端口），
// 路由表 key 一律是 host:port，故这里也用 host:port 拼 key。
// 任何无法解析的情况一律 fail-open（返回 false=保持 h2），未知/未注册 SNI 绝不误关 h2。
func (waf *WafEngine) isHTTP2DisabledForServerName(serverName string, port string) bool {
	if serverName == "" {
		return false
	}
	pureDomain := utils.GetPureDomain(serverName)
	hostKey := pureDomain
	if port != "" {
		hostKey = pureDomain + ":" + port
	}
	rt := waf.rt()

	// 1) 宽松端口：按纯域名映射到具体 host:port
	if hp, ok := rt.HostTargetNoPort[pureDomain]; ok {
		if target, ok := rt.HostTarget[hp]; ok && target != nil {
			return target.Host.DisableHTTP2 == 1
		}
	}
	// 2) 精确 host:port
	if target, ok := rt.HostTarget[hostKey]; ok && target != nil {
		return target.Host.DisableHTTP2 == 1
	}
	// 3) 泛域名 host:port
	if target, ok := rt.HostTarget[domaintool.MaskSubdomain(hostKey)]; ok && target != nil {
		return target.Host.DisableHTTP2 == 1
	}
	// 4) 绑定多域名 domain:port -> code -> HostSafe（含泛域名兜底）
	code, ok := rt.HostTargetMoreDomain[hostKey]
	if !ok {
		code, ok = rt.HostTargetMoreDomain[domaintool.MaskSubdomain(hostKey)]
	}
	if ok {
		if h := rt.HostTarget[rt.HostCode[code]]; h != nil {
			return h.Host.DisableHTTP2 == 1
		}
	}
	// 5) 不指定域名的宽松端口 "*"
	if hp, ok := rt.HostTargetNoPort["*"]; ok {
		if target, ok := rt.HostTarget[hp]; ok && target != nil {
			return target.Host.DisableHTTP2 == 1
		}
	}
	// 6) 通配端口 *:port
	if port != "" {
		if target, ok := rt.HostTarget["*:"+port]; ok && target != nil {
			return target.Host.DisableHTTP2 == 1
		}
	}
	return false
}

// portFromLocalAddr 从连接的本地地址取监听端口（用于按 SNI+port 匹配路由）。
func portFromLocalAddr(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if _, p, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
		return p
	}
	return ""
}

// GetTLSConfigForClient 逐连接按 SNI 定制 ALPN：
// 默认广告 h2+http/1.1；命中的站点 DisableHTTP2==1 时只广告 http/1.1，
// 使原生 WebSocket 客户端(如安卓 uni.connectSocket)不会协商到 h2、握手成功。
// 返回的 config 仍提供 GetCertificate 与版本范围；net/http 在 ServeTLS 时已在 svr.TLSNextProto
// 装好 "h2" 处理器，故广告了 h2 的连接仍会被正确分发到 h2。
func (waf *WafEngine) GetTLSConfigForClient(clientInfo *tls.ClientHelloInfo) (*tls.Config, error) {
	nextProtos := []string{"h2", "http/1.1"}
	if waf.isHTTP2DisabledForServerName(clientInfo.ServerName, portFromLocalAddr(clientInfo.Conn)) {
		nextProtos = []string{"http/1.1"}
	}
	return &tls.Config{
		GetCertificate: waf.GetCertificateFunc,
		MinVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMinVerson),
		MaxVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMaxVerson),
		NextProtos:     nextProtos,
	}, nil
}
