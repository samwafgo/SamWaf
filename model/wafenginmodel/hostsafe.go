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
//
// 并发模型(RCU)：HostSafe 一经发布到路由快照即视为不可变，请求热路径无锁读其字段；
// 运行期热更新一律 copy-on-write(见 wafenginecore/routing_table.go 的 updateHost)，绝不就地改已发布的 HostSafe。
// 例外：LoadBalanceRuntime 是共享可变子对象(每请求轮询状态)，由其自身的 Mux 保护。
type HostSafe struct {
	Rule                *utils.RuleHelper
	TargetHost          string
	RuleData            []model.Rules
	RuleVersionSum      int //规则版本的汇总 通过这个来进行版本动态加载
	Host                model.Hosts
	PluginIpRateLimiter *webplugin.IPRateLimiter //ip限流
	IPWhiteLists        []model.IPAllowList      //ip 白名单
	UrlWhiteLists       []model.URLAllowList     //url 白名单
	LdpUrlLists         []model.LDPUrl           //url 隐私保护

	IPBlockLists       []model.IPBlockList           //ip 黑名单
	UrlBlockLists      []model.URLBlockList          //url 黑名单
	LoadBalanceLists   []model.LoadBalance           //负载均衡
	LoadBalanceRuntime *LoadBalanceRuntime           //负载运行时
	AntiCCBean         model.AntiCC                  //抵御CC
	HttpAuthBases      []model.HttpAuthBase          //HTTP AUTH校验
	BlockingPage       map[string]model.BlockingPage //自定义拦截界面
	CacheRule          []model.CacheRule             //CacheRule
	PathRules          []model.HostPathRule          //路径路由规则
	StaticConfig       model.StaticSiteConfig        //解析后的静态站点安全配置，供路径规则静态服务共享
}

// 负载处理运行对象
type LoadBalanceRuntime struct {
	Mux                     sync.Mutex                           //互斥锁
	CurrentProxyIndex       int                                  //当前Proxy索引
	RevProxies              []*wafproxy.ReverseProxy             //负载均衡里面的数据
	WeightRoundRobinBalance *loadbalance.WeightRoundRobinBalance //权重轮询
	IpHashBalance           *loadbalance.ConsistentHashBalance   //ipHash
}
