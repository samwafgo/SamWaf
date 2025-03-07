package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafproxy"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (waf *WafEngine) ProxyHTTP(w http.ResponseWriter, r *http.Request, host string, remoteUrl *url.URL, clientIp string, ctx context.Context, weblog innerbean.WebLog, hostTarget *wafenginmodel.HostSafe) {

	//检测是否启动负载
	if hostTarget.Host.IsEnableLoadBalance > 0 {
		lb := &hostTarget.LoadBalanceRuntime
		(*lb).Mux.Lock()
		defer (*lb).Mux.Unlock()

		if len(hostTarget.LoadBalanceLists) > 0 && len(hostTarget.LoadBalanceRuntime.RevProxies) == 0 {
			for addrIndex, loadBalance := range hostTarget.LoadBalanceLists {
				//初始化后端负载
				zlog.Debug("HTTP REQUEST", weblog.REQ_UUID, weblog.URL, "未初始化")
				transport, customHeaders := waf.createTransport(r, host, 1, loadBalance, hostTarget)
				customConfig := map[string]string{}
				customConfig["IsTransBackDomain"] = strconv.Itoa(hostTarget.Host.IsTransBackDomain)
				proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(remoteUrl, customHeaders, customConfig)
				proxy.Transport = transport
				proxy.ModifyResponse = waf.modifyResponse()
				proxy.ErrorHandler = waf.errorResponse()
				hostTarget.LoadBalanceRuntime.RevProxies = append(hostTarget.LoadBalanceRuntime.RevProxies, proxy)

				// 初始化策略相关信息
				switch hostTarget.Host.LoadBalanceStage {
				case 1: // 加权轮询（WRR）
					hostTarget.LoadBalanceRuntime.WeightRoundRobinBalance.Add(addrIndex, loadBalance.Weight)
					break
				case 2: // IPHash
					hostTarget.LoadBalanceRuntime.IpHashBalance.Add(strconv.Itoa(addrIndex), 1)
					break
				default:
					http.Error(w, "Invalid Load Balance Stage", http.StatusBadRequest)
				}
			}
		}
		proxyIndex := waf.getProxyIndex(host, clientIp, hostTarget)
		if proxyIndex == -1 {
			http.Error(w, "No Available BackServer", http.StatusBadRequest)
			return
		}
		proxy := hostTarget.LoadBalanceRuntime.RevProxies[proxyIndex]
		if proxy != nil {
			// 添加转发耗时记录
			if wafCtx, ok := ctx.Value("waf_context").(innerbean.WafHttpContextData); ok && wafCtx.Weblog != nil {
				forwardStart := time.Now().UnixNano() / 1e6
				defer func() {
					wafCtx.Weblog.ForwardCost = time.Now().UnixNano()/1e6 - forwardStart
				}()
			}
			proxy.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "No Available Server", http.StatusBadRequest)
		}

	} else {
		transport, customHeaders := waf.createTransport(r, host, 0, model.LoadBalance{}, hostTarget)
		customConfig := map[string]string{}
		customConfig["IsTransBackDomain"] = strconv.Itoa(hostTarget.Host.IsTransBackDomain)
		proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(remoteUrl, customHeaders, customConfig)
		proxy.Transport = transport
		proxy.ModifyResponse = waf.modifyResponse()
		proxy.ErrorHandler = waf.errorResponse()

		// 添加转发耗时记录
		if wafCtx, ok := ctx.Value("waf_context").(innerbean.WafHttpContextData); ok && wafCtx.Weblog != nil {
			forwardStart := time.Now().UnixNano() / 1e6
			defer func() {
				wafCtx.Weblog.ForwardCost = time.Now().UnixNano()/1e6 - forwardStart
			}()
		}

		proxy.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (waf *WafEngine) createTransport(r *http.Request, host string, isEnableLoadBalance int, loadBalance model.LoadBalance, hostTarget *wafenginmodel.HostSafe) (*http.Transport, map[string]string) {
	customHeaders := map[string]string{}
	var transport *http.Transport
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{
			Timeout:   time.Duration(global.GCONFIG_RECORD_CONNECT_TIME_OUT) * time.Second,
			KeepAlive: time.Duration(global.GCONFIG_RECORD_KEEPALIVE_TIME_OUT) * time.Second,
		}
		if isEnableLoadBalance > 0 {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(loadBalance.Remote_ip, strconv.Itoa(loadBalance.Remote_port)))
			if err == nil {
				return conn, nil
			}
		} else {
			if hostTarget.Host.Remote_ip != "" {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(hostTarget.Host.Remote_ip, strconv.Itoa(hostTarget.Host.Remote_port)))
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
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: hostTarget.Host.InsecureSkipVerify == 1,
				GetCertificate:     waf.GetCertificateFunc,
			},
			DialContext: dialContext,
		}
	} else {
		transport = &http.Transport{
			DialContext: dialContext,
		}
	}
	transport.ResponseHeaderTimeout = time.Duration(hostTarget.Host.ResponseTimeOut) * time.Second
	return transport, customHeaders
}
