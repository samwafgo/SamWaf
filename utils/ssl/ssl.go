package ssl

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/model"
	"SamWaf/utils"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/baiducloud"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/huaweicloud"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func RegistrationSSL(order model.SslOrder, savePath string, caServerAddress string, applyPlatform string, eab_kid string, eab_hmac_key string) (model.SslOrder, error) {
	isIpSSL := utils.IsIP(order.ApplyDomain)
	myUser := MyUser{
		Email: order.ApplyEmail,
	}
	if order.ApplyKey == "" {
		// Create a user. New accounts need an email and private key to start.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return order, err
		}
		toPEMPrivate, err := privateKeyToPEM(privateKey)
		if err != nil {
			return order, err
		} else {
			order.ApplyKey = toPEMPrivate
		}
		myUser.key = privateKey
	} else {
		privateKey, err := pemToPrivateKey(order.ApplyKey)
		if err != nil {
			return order, err
		} else {
			myUser.key = privateKey
		}
	}

	//order.ApplyKey = privateKey
	config := lego.NewConfig(&myUser)

	config.CADirURL = caServerAddress
	config.Certificate.KeyType = certcrypto.RSA2048
	if isIpSSL {
		//是否是ip申请ssl证书
		config.Certificate.DisableCommonName = true
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return order, err
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	switch order.ApplyMethod {
	case "http01":
		provider, err := newLoggingWebrootProvider(savePath)
		if err != nil {
			return order, err
		}
		if err = client.Challenge.SetHTTP01Provider(provider); err != nil {
			// 原来这里的 err 被后面的注册流程覆盖掉了，设置失败会静默变成
			// 一次"莫名其妙的校验超时"。不改控制流，但至少要留下证据。
			zlog.Error(fmt.Sprintf("设置HTTP-01 provider失败 域名=%s 错误=%v", order.ApplyDomain, err))
		}
	case "dns01":
		dnsProvider, err := GetDnsProvider(order.ApplyDns)
		if err != nil {
			zlog.Error(fmt.Sprintf("%sDNS校验-初始化渠道失败 渠道=%s 错误=%v", acmeLogPrefix, order.ApplyDns, err))
			return order, err
		}
		err = setDNS01ProviderWithRetry(client, newLoggingDNSProvider(dnsProvider, order.ApplyDns), order.SkipDNSVerify)
		if err != nil {
			zlog.Error(fmt.Sprintf("%sDNS校验-设置provider失败 渠道=%s 错误=%v", acmeLogPrefix, order.ApplyDns, err))
		}
	}

	// New users will need to register
	var reg *registration.Resource
	if applyPlatform == "zerossl" {
		// ZeroSSL 需要使用 EAB (External Account Binding) 方式注册
		eabOptions := registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  eab_kid,
			HmacEncoded:          eab_hmac_key,
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(eabOptions)
		if err != nil {
			return order, err
		}
	} else {
		// 其他平台使用原来的注册方式
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return order, err
		}
	}
	myUser.Registration = reg

	certificates := &certificate.Resource{}
	if !isIpSSL {
		zlog.Info(fmt.Sprintf("%s开始向CA申请域名证书 域名=%s 校验方式=%s 平台=%s",
			acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, applyPlatform))
		request := certificate.ObtainRequest{
			Domains: strings.Split(order.ApplyDomain, ","),
			Bundle:  true,
		}
		certificatesLocal, err := client.Certificate.Obtain(request)

		if err != nil {
			zlog.Error(fmt.Sprintf("%s向CA申请域名证书失败 域名=%s 校验方式=%s 错误=%v",
				acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, err))
			return order, err
		}
		certificates = certificatesLocal
	} else {
		// IP 证书：CA 侧走 CSR 方式，且只签发 shortlived（短周期）证书，
		// 有效期只有几天，完全依赖自动续期，所以这条路径的日志比域名证书更重要。
		zlog.Info(fmt.Sprintf("%sIP证书-开始申请 IP=%s 校验方式=%s(IP证书仅支持文件验证) 证书类型=shortlived(短周期) 平台=%s",
			acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, applyPlatform))

		// 1. 为证书生成新的私钥
		certPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			zlog.Error(fmt.Sprintf("%sIP证书-生成私钥失败 IP=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
			return order, fmt.Errorf("generate cert private key failed: %w", err)
		}

		// 2. 用新私钥创建 CSR
		csrDER, err := x509.CreateCertificateRequest(
			rand.Reader,
			&x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				IPAddresses: []net.IP{net.ParseIP(order.ApplyDomain)},
			},
			certPrivateKey, // 使用证书专用私钥
		)
		if err != nil {
			return order, err
		}

		// 3. 解析 CSR
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return order, err
		}

		// 4. 申请证书
		certificatesLocal, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
			CSR:        csr,
			Bundle:     true,
			PrivateKey: certPrivateKey, //  使用证书专用私钥
			Profile:    "shortlived",
		})
		if err != nil {
			zlog.Error(fmt.Sprintf("%sIP证书-向CA申请失败 IP=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
			return order, err
		}
		certificates = certificatesLocal
	}
	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.

	order.ResultPrivateKey = certificates.PrivateKey
	order.ResultCertificate = certificates.Certificate
	order.ResultCertStableURL = certificates.CertStableURL
	order.ResultCertURL = certificates.CertURL
	order.ResultCSR = certificates.CSR
	// IP证书情况下，certificates.Domain可能为空，使用申请的IP地址
	if isIpSSL && certificates.Domain == "" {
		order.ResultDomain = order.ApplyDomain
	} else {
		order.ResultDomain = certificates.Domain
	}
	order.ResultIssuerCertificate = certificates.IssuerCertificate
	block, _ := pem.Decode(order.ResultCertificate)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			order.ResultValidTo = customtype.JsonTime(cert.NotAfter)
			zlog.Info(fmt.Sprintf("%s证书签发成功 申请对象=%s 校验方式=%s 有效期至=%s",
				acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, cert.NotAfter.Format("2006-01-02 15:04:05")))
		} else {
			zlog.Warn(fmt.Sprintf("%s证书已签发但解析有效期失败 申请对象=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
		}
	}

	return order, nil
}

func ReNewSSL(order model.SslOrder, savePath string, caServerAddress string, applyPlatform string, eab_kid string, eab_hmac_key string) (model.SslOrder, error) {
	// 判断是否是IP证书
	isIpSSL := utils.IsIP(order.ApplyDomain)

	myUser := MyUser{
		Email: order.ApplyEmail,
	}
	if order.ApplyKey == "" {
		// Create a user. New accounts need an email and private key to start.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return order, err
		}
		toPEMPrivate, err := privateKeyToPEM(privateKey)
		if err != nil {
			return order, err
		} else {
			order.ApplyKey = toPEMPrivate
		}
		myUser.key = privateKey
	} else {
		privateKey, err := pemToPrivateKey(order.ApplyKey)
		if err != nil {
			return order, err
		} else {
			myUser.key = privateKey
		}
	}

	//order.ApplyKey = privateKey
	config := lego.NewConfig(&myUser)
	config.CADirURL = caServerAddress
	config.Certificate.KeyType = certcrypto.RSA2048

	if isIpSSL {
		//是否是ip申请ssl证书
		config.Certificate.DisableCommonName = true
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return order, err
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	if order.ApplyMethod == "http01" {
		// 续期与申请必须走同一个 provider：否则"申请时看得见、续期时看不见"，
		// 而续期恰恰是无人值守的那一次，出问题更需要日志。
		provider, err := newLoggingWebrootProvider(savePath)
		if err != nil {
			return order, err
		}
		if err = client.Challenge.SetHTTP01Provider(provider); err != nil {
			zlog.Error(fmt.Sprintf("续期设置HTTP-01 provider失败 域名=%s 错误=%v", order.ApplyDomain, err))
		}
	} else if order.ApplyMethod == "dns01" {
		// 与申请走同一套包装：续期是无人值守的那一次，日志比申请时更要紧
		dnsProvider, err := GetDnsProvider(order.ApplyDns)
		if err != nil {
			zlog.Error(fmt.Sprintf("%s续期-DNS校验-初始化渠道失败 渠道=%s 错误=%v", acmeLogPrefix, order.ApplyDns, err))
			return order, err
		}
		err = setDNS01ProviderWithRetry(client, newLoggingDNSProvider(dnsProvider, order.ApplyDns), order.SkipDNSVerify)
		if err != nil {
			zlog.Error(fmt.Sprintf("%s续期-DNS校验-设置provider失败 渠道=%s 错误=%v", acmeLogPrefix, order.ApplyDns, err))
		}
	}
	// New users will need to register
	var reg *registration.Resource
	if applyPlatform == "zerossl" {
		// ZeroSSL 需要使用 EAB (External Account Binding) 方式注册
		eabOptions := registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  eab_kid,
			HmacEncoded:          eab_hmac_key,
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(eabOptions)
		if err != nil {
			return order, err
		}
	} else {
		// 其他平台使用原来的注册方式
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return order, err
		}
	}
	myUser.Registration = reg

	certificates := &certificate.Resource{}

	if !isIpSSL {
		// 域名证书：使用续期方式
		zlog.Info(fmt.Sprintf("%s续期-开始向CA续期域名证书 域名=%s 校验方式=%s 平台=%s",
			acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, applyPlatform))
		certRes := certificate.Resource{
			Domain:            order.ResultDomain,
			CertURL:           order.ResultCertURL,
			CertStableURL:     order.ResultCertStableURL,
			PrivateKey:        order.ResultPrivateKey,
			Certificate:       order.ResultCertificate,
			IssuerCertificate: order.ResultIssuerCertificate,
			CSR:               order.ResultCSR,
		}
		//构造参数
		certificatesLocal, err := client.Certificate.RenewWithOptions(certRes, &certificate.RenewOptions{
			Bundle: true,
		})
		if err != nil {
			zlog.Error(fmt.Sprintf("%s续期-向CA续期域名证书失败 域名=%s 校验方式=%s 错误=%v",
				acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, err))
			return order, err
		}
		certificates = certificatesLocal
	} else {
		// IP证书：使用CSR方式重新申请
		zlog.Info(fmt.Sprintf("%s续期-IP证书-开始重新申请 IP=%s 校验方式=%s 证书类型=shortlived(短周期) 平台=%s",
			acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, applyPlatform))

		// 1. 为证书生成新的私钥
		certPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			zlog.Error(fmt.Sprintf("%s续期-IP证书-生成私钥失败 IP=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
			return order, fmt.Errorf("generate cert private key failed: %w", err)
		}

		// 2. 用新私钥创建 CSR
		csrDER, err := x509.CreateCertificateRequest(
			rand.Reader,
			&x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "",
				},
				IPAddresses: []net.IP{net.ParseIP(order.ApplyDomain)},
			},
			certPrivateKey, // 使用证书专用私钥
		)
		if err != nil {
			return order, err
		}

		// 3. 解析 CSR
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return order, err
		}

		// 4. 申请新证书
		certificatesLocal, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
			CSR:        csr,
			Bundle:     true,
			PrivateKey: certPrivateKey, // 使用证书专用私钥
			Profile:    "shortlived",
		})
		if err != nil {
			zlog.Error(fmt.Sprintf("%s续期-IP证书-向CA申请失败 IP=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
			return order, err
		}
		certificates = certificatesLocal
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.

	order.ResultPrivateKey = certificates.PrivateKey
	order.ResultCertificate = certificates.Certificate
	order.ResultCertStableURL = certificates.CertStableURL
	order.ResultCertURL = certificates.CertURL
	order.ResultCSR = certificates.CSR
	// IP证书情况下，certificates.Domain可能为空，使用申请的IP地址
	if isIpSSL && certificates.Domain == "" {
		order.ResultDomain = order.ApplyDomain
	} else {
		order.ResultDomain = certificates.Domain
	}
	order.ResultIssuerCertificate = certificates.IssuerCertificate
	block, _ := pem.Decode(order.ResultCertificate)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			order.ResultValidTo = customtype.JsonTime(cert.NotAfter)
			zlog.Info(fmt.Sprintf("%s续期-证书续期成功 申请对象=%s 校验方式=%s 有效期至=%s",
				acmeLogPrefix, order.ApplyDomain, order.ApplyMethod, cert.NotAfter.Format("2006-01-02 15:04:05")))
		} else {
			zlog.Warn(fmt.Sprintf("%s续期-证书已签发但解析有效期失败 申请对象=%s 错误=%v", acmeLogPrefix, order.ApplyDomain, err))
		}
	}
	return order, nil
}

// 将ECDSA私钥编码为PEM格式的字符串
func privateKeyToPEM(privateKey *ecdsa.PrivateKey) (string, error) {
	// 将私钥转换为DER格式字节
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}

	// 将DER格式字节封装为PEM格式
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	return string(pemKey), nil
}

// 将PEM格式字符串转换回ECDSA私钥
func pemToPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	// 解码PEM字符串
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	// 解析DER格式的私钥
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func GetDnsProvider(dnsName string) (challenge.Provider, error) {

	switch dnsName {
	case "alidns":
		return alidns.NewDNSProvider()
	case "huaweicloud":
		return huaweicloud.NewDNSProvider()
	case "tencentcloud":
		return tencentcloud.NewDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "baiducloud":
		return baiducloud.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", dnsName)
	}
}

func setDNS01ProviderWithRetry(client *lego.Client, dnsProvider challenge.Provider, skipDNSVerify int64) error {
	// 默认重试10次，每次间隔30秒
	dnsPrecheckRetry := 10
	dnsPrecheckRetryInterval := 30 * time.Second

	// DNS 传播等待时间：300秒（3分钟）
	propagationTimeout := 180 * time.Second

	if skipDNSVerify == 1 {
		// 跳过本地DNS传播校验：固定等待后直接通知CA进行验证
		zlog.Info(fmt.Sprintf("%sDNS校验-已按配置跳过本地传播校验，固定等待 %v 后直接通知CA", acmeLogPrefix, propagationTimeout))
		return client.Challenge.SetDNS01Provider(dnsProvider, dns01.PropagationWait(propagationTimeout, true))
	}
	zlog.Info(fmt.Sprintf("%sDNS校验-启用本地传播校验 最多重试%d次 间隔%v", acmeLogPrefix, dnsPrecheckRetry, dnsPrecheckRetryInterval))

	// 默认执行本地DNS传播校验，并增加重试机制
	return client.Challenge.SetDNS01Provider(dnsProvider,
		dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			var lastErr error
			for i := 1; i <= dnsPrecheckRetry; i++ {
				ok, err := check(fqdn, value)
				if ok && err == nil {
					zlog.Info(fmt.Sprintf("%sDNS校验-传播校验通过(第%d/%d次) 域名=%s 记录=TXT %s",
						acmeLogPrefix, i, dnsPrecheckRetry, domain, fqdn))
					return true, nil
				}
				lastErr = err
				// 这里是 DNS 方式最常卡住的一步：记录写进去了但还没传播开。
				// 每次探测都留一行，用户能看出是"一直没生效"还是"快好了"。
				zlog.Warn(fmt.Sprintf("%sDNS校验-传播尚未生效(第%d/%d次) 域名=%s 记录=TXT %s 期望值=%s 错误=%v",
					acmeLogPrefix, i, dnsPrecheckRetry, domain, fqdn, value, err))
				if i < dnsPrecheckRetry {
					time.Sleep(dnsPrecheckRetryInterval)
				}
			}

			if lastErr != nil {
				zlog.Error(fmt.Sprintf("%sDNS校验-传播校验最终失败 域名=%s 记录=TXT %s 错误=%v 处置建议=用 dig txt %s 自查，或在申请时勾选跳过DNS传播校验",
					acmeLogPrefix, domain, fqdn, lastErr, fqdn))
				return false, lastErr
			}
			zlog.Error(fmt.Sprintf("%sDNS校验-传播校验重试%d次仍未通过 域名=%s 记录=TXT %s", acmeLogPrefix, dnsPrecheckRetry, domain, fqdn))
			return false, fmt.Errorf("dns propagation precheck failed after %d retries", dnsPrecheckRetry)
		}),
	)
}
