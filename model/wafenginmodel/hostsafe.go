package wafenginmodel

import (
	"SamWaf/model"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/wafproxy"
	"sync"
)

// 主机安全配置
type HostSafe struct {
	Mux                 sync.Mutex   //互斥锁
	LoadBalance         *LoadBalance //负载
	Rule                *utils.RuleHelper
	TargetHost          string
	RuleData            []model.Rules
	RuleVersionSum      int //规则版本的汇总 通过这个来进行版本动态加载
	Host                model.Hosts
	PluginIpRateLimiter *plugin.IPRateLimiter //ip限流
	IPWhiteLists        []model.IPAllowList   //ip 白名单
	UrlWhiteLists       []model.URLAllowList  //url 白名单
	LdpUrlLists         []model.LDPUrl        //url 隐私保护

	IPBlockLists  []model.IPBlockList  //ip 黑名单
	UrlBlockLists []model.URLBlockList //url 黑名单

}

// 负载处理
type LoadBalance struct {
	IsEnable          bool                     //是否激活负载
	LoadBalanceStage  int                      //负载策略
	CurrentProxyIndex int                      //当前Proxy索引
	RevProxies        []*wafproxy.ReverseProxy //负载均衡里面的数据
}
