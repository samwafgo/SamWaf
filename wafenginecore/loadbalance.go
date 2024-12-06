package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/model/wafenginmodel"
	"strconv"
)

func (waf *WafEngine) getProxyIndex(host string, ip string, hostTarget *wafenginmodel.HostSafe) int {
	bestAddr := -1
	// 根据负载均衡策略处理请求
	switch hostTarget.Host.LoadBalanceStage {
	case 1: // 加权轮询（WRR）
		addrIndex, err := hostTarget.LoadBalanceRuntime.WeightRoundRobinBalance.Get()
		if err != nil {
			zlog.Error("Invalid Load Balance")
		}
		bestAddr = addrIndex

	case 2: // IP Hash
		addrIndexString, err := hostTarget.LoadBalanceRuntime.IpHashBalance.Get(ip)
		if err != nil {
			zlog.Error("Invalid Load Balance")
		}
		addrIndex, _ := strconv.Atoi(addrIndexString)
		bestAddr = addrIndex
	case 3: // 加权最小连接数（WLC）
		//waf.handleWeightedLeastConnections(w, r, ctx, lb)
	default:
		//http.Error(w, "Invalid Load Balance Stage", http.StatusBadRequest)
	}
	return bestAddr
}
