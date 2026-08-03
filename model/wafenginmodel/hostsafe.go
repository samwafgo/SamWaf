package wafenginmodel

import (
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafenginecore/ipset"
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

	IPBlockLists []model.IPBlockList //ip 黑名单
	IPBlockIndex *ipset.MatchSet     //ip 黑名单编译后的快速索引(手工小名单，可空；nil 时回退 IPBlockLists 线性遍历)
	IPWhiteIndex *ipset.MatchSet     //ip 白名单编译后的快速索引(可空；nil 时回退 IPWhiteLists 线性遍历)
	// IPBlockGroupCodes / IPWhiteGroupCodes 是本站黑/白名单里引用的 IP 组短码（冷加载与热更新时预抽出，
	// 避免请求热路径线性扫名单找组引用行）。真正的组内容不放这里，而是查 ipset 的全局原子快照——
	// 那样改一次组就能让所有引用站点(含全局网站)同时生效，不必逐站点重建 HostSafe。
	// 与其它字段一样受 RCU 约束：发布后不可就地 append 或改元素，热更新必须整体替换新切片。
	IPBlockGroupCodes  []string
	IPWhiteGroupCodes  []string
	UrlBlockLists      []model.URLBlockList          //url 黑名单
	LoadBalanceLists   []model.LoadBalance           //负载均衡
	LoadBalanceRuntime *LoadBalanceRuntime           //负载运行时
	AntiCCBean         model.AntiCC                  //抵御CC
	HttpAuthBases      []model.HttpAuthBase          //HTTP AUTH校验
	BlockingPage       map[string]model.BlockingPage //自定义拦截界面
	CacheRule          []model.CacheRule             //CacheRule
	TamperRules        []model.TamperRule            //网页防篡改规则（含基线正文，供响应比对/回吐）
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
