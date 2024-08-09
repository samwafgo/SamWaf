package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/utils/zlog"
	"SamWaf/wafproxy"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (waf *WafEngine) ProxyHTTP(w http.ResponseWriter, r *http.Request, host string, remoteUrl *url.URL, ctx context.Context, weblog innerbean.WebLog) {
	lb := waf.HostTarget[host].LoadBalance
	if len(lb.RevProxies) > 0 {
		zlog.Debug("HTTP REQUEST", weblog.REQ_UUID, weblog.URL, "已初始化")
		lb.RevProxies[0].ServeHTTP(w, r.WithContext(ctx))
		return
	}
	zlog.Debug("HTTP REQUEST", weblog.REQ_UUID, weblog.URL, "未初始化")

	transport, customHeaders := waf.createTransport(r, host)
	proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(remoteUrl, customHeaders)
	proxy.Transport = transport
	proxy.ModifyResponse = waf.modifyResponse()
	proxy.ErrorHandler = errorHandler()

	lb.RevProxies = append(lb.RevProxies, proxy)
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (waf *WafEngine) createTransport(r *http.Request, host string) (*http.Transport, map[string]string) {
	customHeaders := map[string]string{}
	var transport *http.Transport
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		if waf.HostTarget[host].Host.Remote_ip != "" {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(waf.HostTarget[host].Host.Remote_ip, strconv.Itoa(waf.HostTarget[host].Host.Remote_port)))
			if err == nil {
				return conn, nil
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}

	if r.TLS != nil {
		// 增加https标识
		customHeaders["X-FORWARDED-PROTO"] = "https"

		hostParts := strings.Split(host, ":")
		port := "443"
		if len(hostParts) == 2 {
			port = hostParts[1]
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				NameToCertificate:  make(map[string]*tls.Certificate, 0),
				InsecureSkipVerify: false,
			},
			DialContext: dialContext,
		}
		portInt, _ := strconv.Atoi(port)

		transport.TLSClientConfig.NameToCertificate = waf.AllCertificate[portInt]
		transport.TLSClientConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if x509Cert, ok := transport.TLSClientConfig.NameToCertificate[clientInfo.ServerName]; ok {
				return x509Cert, nil
			}
			return nil, errors.New("config error")
		}
	} else {
		transport = &http.Transport{
			DialContext: dialContext,
		}
	}
	return transport, customHeaders
}
