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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (waf *WafEngine) ProxyHTTP(w http.ResponseWriter, r *http.Request, host string, remoteUrl *url.URL, clientIp string, ctx context.Context, weblog *innerbean.WebLog, hostTarget *wafenginmodel.HostSafe) {

	//检测是否启动负载
	if hostTarget.Host.IsEnableLoadBalance > 0 {
		lb := &hostTarget.LoadBalanceRuntime
		(*lb).Mux.Lock()
		defer (*lb).Mux.Unlock()

		if len(hostTarget.LoadBalanceLists) > 0 && len(hostTarget.LoadBalanceRuntime.RevProxies) == 0 {
			for addrIndex, loadBalance := range hostTarget.LoadBalanceLists {
				//初始化后端负载
				zlog.Debug("HTTP REQUEST", weblog.REQ_UUID, weblog.URL, "未初始化")
				transport := waf.getOrCreateTransport(r, host, 1, loadBalance, hostTarget) // 使用缓存的Transport
				customHeaders := waf.getCustomHeaders(r, host, 1, loadBalance, hostTarget)
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

		// 记录使用的负载均衡IP和端口信息
		if proxyIndex >= 0 && proxyIndex < len(hostTarget.LoadBalanceLists) {
			selectedLoadBalance := hostTarget.LoadBalanceLists[proxyIndex]
			balanceInfo := fmt.Sprintf("%s:%d", selectedLoadBalance.Remote_ip, selectedLoadBalance.Remote_port)

			// 记录到WebLog的BalanceInfo字段
			weblog.BalanceInfo = balanceInfo
		}

		proxy := hostTarget.LoadBalanceRuntime.RevProxies[proxyIndex]
		if proxy != nil {
			// 添加转发耗时记录
			if wafCtx, ok := ctx.Value("waf_context").(innerbean.WafHttpContextData); ok && wafCtx.Weblog != nil {
				forwardStart := time.Now().UnixNano() / 1e6
				defer func() {
					wafCtx.Weblog.ForwardCost = time.Now().UnixNano()/1e6 - forwardStart
					wafCtx.Weblog.IsBalance = 1
				}()
			}
			proxy.ServeHTTP(w, r.WithContext(ctx))
		} else {
			http.Error(w, "No Available Server", http.StatusBadRequest)
		}

	} else {
		transport := waf.getOrCreateTransport(r, host, 0, model.LoadBalance{}, hostTarget) // 使用缓存的Transport
		customHeaders := waf.getCustomHeaders(r, host, 0, model.LoadBalance{}, hostTarget)
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
				wafCtx.Weblog.IsBalance = 0
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

	// 解析并应用Transport配置
	transportConfig := model.ParseTransportConfig(hostTarget.Host.TransportJSON)

	// 应用Transport配置（只有非零值才设置）
	if transportConfig.MaxIdleConns > 0 {
		transport.MaxIdleConns = transportConfig.MaxIdleConns
	}
	if transportConfig.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = transportConfig.MaxIdleConnsPerHost
	}
	if transportConfig.MaxConnsPerHost > 0 {
		transport.MaxConnsPerHost = transportConfig.MaxConnsPerHost
	}
	if transportConfig.IdleConnTimeout > 0 {
		transport.IdleConnTimeout = time.Duration(transportConfig.IdleConnTimeout) * time.Second
	}
	if transportConfig.TLSHandshakeTimeout > 0 {
		transport.TLSHandshakeTimeout = time.Duration(transportConfig.TLSHandshakeTimeout) * time.Second
	}
	if transportConfig.ExpectContinueTimeout > 0 {
		transport.ExpectContinueTimeout = time.Duration(transportConfig.ExpectContinueTimeout) * time.Second
	}

	transport.ResponseHeaderTimeout = time.Duration(hostTarget.Host.ResponseTimeOut) * time.Second

	//把下面的参数一次性使用格式化实现
	zlog.Debug(fmt.Sprintf("Transport配置信息:\nMaxIdleConns: %d\nMaxIdleConnsPerHost: %d\nMaxConnsPerHost: %d\nIdleConnTimeout: %v\nTLSHandshakeTimeout: %v\nExpectContinueTimeout: %v\nResponseHeaderTimeout: %v\nDisableKeepAlives: %v\nDisableCompression: %v",
		transport.MaxIdleConns,
		transport.MaxIdleConnsPerHost,
		transport.MaxConnsPerHost,
		transport.IdleConnTimeout,
		transport.TLSHandshakeTimeout,
		transport.ExpectContinueTimeout,
		transport.ResponseHeaderTimeout,
		transport.DisableKeepAlives,
		transport.DisableCompression))
	return transport, customHeaders
}

// 获取或创建Transport
func (waf *WafEngine) getOrCreateTransport(r *http.Request, host string, isEnableLoadBalance int, loadBalance model.LoadBalance, hostTarget *wafenginmodel.HostSafe) *http.Transport {
	// 生成Transport的唯一键
	transportKey := waf.generateTransportKey(host, isEnableLoadBalance, loadBalance, hostTarget)

	waf.TransportMux.RLock()
	if transport, exists := waf.TransportPool[transportKey]; exists {
		waf.TransportMux.RUnlock()
		return transport
	}
	waf.TransportMux.RUnlock()

	// 创建新的Transport
	waf.TransportMux.Lock()
	defer waf.TransportMux.Unlock()

	// 双重检查，防止并发创建
	if transport, exists := waf.TransportPool[transportKey]; exists {
		return transport
	}

	transport, _ := waf.createTransport(r, host, isEnableLoadBalance, loadBalance, hostTarget)

	// 优化Transport配置
	/*transport.MaxIdleConns = 1000
	transport.MaxIdleConnsPerHost = 1000*/

	if waf.TransportPool == nil {
		waf.TransportPool = make(map[string]*http.Transport)
	}
	waf.TransportPool[transportKey] = transport

	return transport
}

// 生成Transport的唯一键
func (waf *WafEngine) generateTransportKey(host string, isEnableLoadBalance int, loadBalance model.LoadBalance, hostTarget *wafenginmodel.HostSafe) string {
	key := fmt.Sprintf("%s_%d_%s_%d_%v",
		host,
		isEnableLoadBalance,
		loadBalance.Remote_ip,
		loadBalance.Remote_port,
		hostTarget.Host.InsecureSkipVerify)
	return key
}

// 分离自定义头部逻辑
func (waf *WafEngine) getCustomHeaders(r *http.Request, host string, isEnableLoadBalance int, loadBalance model.LoadBalance, hostTarget *wafenginmodel.HostSafe) map[string]string {
	customHeaders := map[string]string{}
	if r.TLS != nil {
		customHeaders["X-FORWARDED-PROTO"] = "https"
	}
	return customHeaders
}
