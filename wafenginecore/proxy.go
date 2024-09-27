package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
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

func (waf *WafEngine) ProxyHTTP(w http.ResponseWriter, r *http.Request, host string, remoteUrl *url.URL, clientIp string, ctx context.Context, weblog innerbean.WebLog) {
	//检测是否启动负载
	if waf.HostTarget[host].Host.IsEnableLoadBalance > 0 {
		lb := &waf.HostTarget[host].LoadBalanceRuntime
		(*lb).Mux.Lock()
		defer (*lb).Mux.Unlock()

		if len(waf.HostTarget[host].LoadBalanceLists) > 0 && len(waf.HostTarget[host].LoadBalanceRuntime.RevProxies) == 0 {
			for addrIndex, loadBalance := range waf.HostTarget[host].LoadBalanceLists {
				//初始化后端负载
				zlog.Debug("HTTP REQUEST", weblog.REQ_UUID, weblog.URL, "未初始化")
				transport, customHeaders := waf.createTransport(r, host, 1, loadBalance)
				proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(remoteUrl, customHeaders)
				proxy.Transport = transport
				proxy.ModifyResponse = waf.modifyResponse()
				proxy.ErrorHandler = waf.errorResponse()
				waf.HostTarget[host].LoadBalanceRuntime.RevProxies = append(waf.HostTarget[host].LoadBalanceRuntime.RevProxies, proxy)

				// 初始化策略相关信息
				switch waf.HostTarget[host].Host.LoadBalanceStage {
				case 1: // 加权轮询（WRR）
					waf.HostTarget[host].LoadBalanceRuntime.WeightRoundRobinBalance.Add(addrIndex, loadBalance.Weight)
					break
				case 2: // IPHash
					waf.HostTarget[host].LoadBalanceRuntime.IpHashBalance.Add(strconv.Itoa(addrIndex), 1)
					break
				default:
					http.Error(w, "Invalid Load Balance Stage", http.StatusBadRequest)
				}
			}
		}
		proxyIndex := waf.getProxyIndex(host, clientIp)
		if proxyIndex == -1 {
			http.Error(w, "No Available BackServer", http.StatusBadRequest)
			return
		}
		proxy := waf.HostTarget[host].LoadBalanceRuntime.RevProxies[proxyIndex]
		if proxy != nil {
			proxy.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "No Available Server", http.StatusBadRequest)
		}

	} else {
		transport, customHeaders := waf.createTransport(r, host, 0, model.LoadBalance{})
		proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(remoteUrl, customHeaders)
		proxy.Transport = transport
		proxy.ModifyResponse = waf.modifyResponse()
		proxy.ErrorHandler = waf.errorResponse()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (waf *WafEngine) createTransport(r *http.Request, host string, isEnableLoadBalance int, loadBalance model.LoadBalance) (*http.Transport, map[string]string) {
	customHeaders := map[string]string{}
	var transport *http.Transport
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		if isEnableLoadBalance > 0 {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(loadBalance.Remote_ip, strconv.Itoa(loadBalance.Remote_port)))
			if err == nil {
				return conn, nil
			}
		} else {
			if waf.HostTarget[host].Host.Remote_ip != "" {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(waf.HostTarget[host].Host.Remote_ip, strconv.Itoa(waf.HostTarget[host].Host.Remote_port)))
				if err == nil {
					return conn, nil
				}
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
