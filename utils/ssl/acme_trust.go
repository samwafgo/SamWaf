package ssl

import (
	"SamWaf/utils"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"golang.org/x/net/idna"
)

const maxACMECAPEMBytes = 1 << 20

var errACMEOriginMismatch = errors.New("自定义 CA 的请求必须与 ACME 目录同源")

func newTrustedACMEConfig(user *MyUser, roots *x509.CertPool) *lego.Config {
	// 自定义信任使用独立客户端，不读取 lego 的进程级 TLS 环境变量。
	return &lego.Config{
		User: user,
		Certificate: lego.CertificateConfig{
			KeyType: certcrypto.RSA2048,
			Timeout: 30 * time.Second,
		},
		HTTPClient: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				TLSHandshakeTimeout:   30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				TLSClientConfig:       &tls.Config{RootCAs: roots},
			},
		},
	}
}

func loadACMECAFile(baseDir, name string) (*x509.CertPool, error) {
	if baseDir == "" || !utils.IsValidACMECAFilename(name) {
		return nil, errors.New("CA 文件必须是 conf/acme-ca 下的 PEM 文件名")
	}
	base, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, errors.New("无法打开 SamWaf 实例目录")
	}
	defer base.Close()
	conf, err := openACMECAFolder(base, "conf")
	if err != nil {
		return nil, err
	}
	defer conf.Close()
	root, err := openACMECAFolder(conf, "acme-ca")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("conf/acme-ca/%s 不存在或不可访问", name)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("conf/acme-ca/%s 必须是普通文件", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("无法打开 conf/acme-ca/%s", name)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("conf/acme-ca/%s 必须是普通文件", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxACMECAPEMBytes+1))
	if err != nil {
		return nil, fmt.Errorf("无法读取 conf/acme-ca/%s", name)
	}
	if len(data) > maxACMECAPEMBytes {
		return nil, fmt.Errorf("conf/acme-ca/%s 超过 1 MiB", name)
	}
	roots, err := parseACMECARoots(data)
	if err != nil {
		return nil, fmt.Errorf("conf/acme-ca/%s：%w", name, err)
	}
	return roots, nil
}

func openACMECAFolder(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil || info.Mode().Type() != os.ModeDir {
		return nil, errors.New("conf/acme-ca 不存在或不是普通目录")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, errors.New("无法打开 conf/acme-ca")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return nil, errors.New("conf/acme-ca 目录已变化，请重试")
	}
	return root, nil
}

func parseACMECARoots(data []byte) (*x509.CertPool, error) {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	roots := x509.NewCertPool()
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("CA 证书文件为空")
	}
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte(begin)) {
			return nil, errors.New("只接受 PEM 格式的 CA 证书")
		}
		endAt := bytes.Index(data, []byte(end))
		if endAt < len(begin) || bytes.Contains(data[len(begin):endAt], []byte("-----BEGIN ")) {
			return nil, errors.New("无效的 PEM 证书")
		}
		endAt += len(end)
		block, rest := pem.Decode(data[:endAt])
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return nil, errors.New("无效的 PEM 证书")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, errors.New("无法解析 CA 证书或证书不是 CA")
		}
		roots.AddCert(cert)
		data = bytes.TrimSpace(data[endAt:])
	}
	return roots, nil
}

func sameACMEOrigin(allowed, target *url.URL) bool {
	if target.Scheme != "https" || target.User != nil || acmeHTTPSPort(allowed) != acmeHTTPSPort(target) {
		return false
	}
	allowedHost, targetHost := acmeOriginHost(allowed.Hostname()), acmeOriginHost(target.Hostname())
	return allowedHost != "" && allowedHost == targetHost
}

func acmeOriginHost(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return ""
	}
	return strings.ToLower(ascii)
}

func acmeHTTPSPort(u *url.URL) uint64 {
	if u.Port() == "" && !strings.HasSuffix(u.Host, ":") {
		return 443
	}
	port, _ := strconv.ParseUint(u.Port(), 10, 16)
	return port
}
