package ssl

import (
	"SamWaf/model"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/huaweicloud"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
	"strings"
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

func RegistrationSSL(order model.SslOrder, savePath string) (model.SslOrder, error) {
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

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = lego.LEDirectoryProduction //  测试用 LEDirectoryStaging  正式用 LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

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
		provider, err := webroot.NewHTTPProvider(savePath)
		if err != nil {
			return order, err
		}
		err = client.Challenge.SetHTTP01Provider(provider)
	} else if order.ApplyMethod == "dns01" {
		dnsProvider, err := GetDnsProvider(order.ApplyDns)
		if err != nil {
			return order, err
		}
		err = client.Challenge.SetDNS01Provider(dnsProvider)
	}

	if err != nil {
		return order, err
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return order, err
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: strings.Split(order.ApplyDomain, ","),
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return order, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	order.ResultPrivateKey = certificates.PrivateKey
	order.ResultCertificate = certificates.Certificate
	order.ResultCertStableURL = certificates.CertStableURL
	order.ResultCertURL = certificates.CertURL
	order.ResultCSR = certificates.CSR
	order.ResultDomain = certificates.Domain
	order.ResultIssuerCertificate = certificates.IssuerCertificate
	block, _ := pem.Decode(order.ResultCertificate)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			order.ResultValidTo = cert.NotAfter
		}
	}

	return order, nil
}

func ReNewSSL(order model.SslOrder, savePath string) (model.SslOrder, error) {
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

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = lego.LEDirectoryProduction // 测试用 LEDirectoryStaging  正式用 LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

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
		provider, err := webroot.NewHTTPProvider(savePath)
		if err != nil {
			return order, err
		}
		err = client.Challenge.SetHTTP01Provider(provider)
	} else if order.ApplyMethod == "dns01" {
		dnsProvider, err := GetDnsProvider(order.ApplyDns)
		if err != nil {
			return order, err
		}
		err = client.Challenge.SetDNS01Provider(dnsProvider)
	}

	if err != nil {
		return order, err
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return order, err
	}
	myUser.Registration = reg

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
	certificates, err := client.Certificate.RenewWithOptions(certRes, &certificate.RenewOptions{
		Bundle: true,
	})
	if err != nil {
		return order, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	order.ResultPrivateKey = certificates.PrivateKey
	order.ResultCertificate = certificates.Certificate
	order.ResultCertStableURL = certificates.CertStableURL
	order.ResultCertURL = certificates.CertURL
	order.ResultCSR = certificates.CSR
	order.ResultDomain = certificates.Domain
	order.ResultIssuerCertificate = certificates.IssuerCertificate
	block, _ := pem.Decode(order.ResultCertificate)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			order.ResultValidTo = cert.NotAfter
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
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", dnsName)
	}
}
