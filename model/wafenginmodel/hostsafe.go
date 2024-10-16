package wafenginmodel

import (
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafenginecore/loadbalance"
	"SamWaf/wafproxy"
	"SamWaf/webplugin"
	"sync"
)

// 主机安全配置
type HostSafe struct {
	Mux                 sync.Mutex //互斥锁
	Rule                *utils.RuleHelper
	TargetHost          string
	RuleData            []model.Rules
	RuleVersionSum      int //规则版本的汇总 通过这个来进行版本动态加载
	Host                model.Hosts
	PluginIpRateLimiter *webplugin.IPRateLimiter //ip限流
	IPWhiteLists        []model.IPAllowList      //ip 白名单
	UrlWhiteLists       []model.URLAllowList     //url 白名单
	LdpUrlLists         []model.LDPUrl           //url 隐私保护

	IPBlockLists       []model.IPBlockList  //ip 黑名单
	UrlBlockLists      []model.URLBlockList //url 黑名单
	LoadBalanceLists   []model.LoadBalance  //负载均衡
	LoadBalanceRuntime *LoadBalanceRuntime  //负载运行时
}

// 负载处理运行对象
type LoadBalanceRuntime struct {
	Mux                     sync.Mutex                           //互斥锁
	CurrentProxyIndex       int                                  //当前Proxy索引
	RevProxies              []*wafproxy.ReverseProxy             //负载均衡里面的数据
	WeightRoundRobinBalance *loadbalance.WeightRoundRobinBalance //权重轮询
	IpHashBalance           *loadbalance.ConsistentHashBalance   //ipHash
}
