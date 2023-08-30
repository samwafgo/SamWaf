package wafenginmodel

import (
	"SamWaf/model"
	"SamWaf/plugin"
	"SamWaf/utils"
	"net/http/httputil"
	"sync"
)

// 主机安全配置
type HostSafe struct {
	Mux                 sync.Mutex //互斥锁
	RevProxy            *httputil.ReverseProxy
	Rule                *utils.RuleHelper
	TargetHost          string
	RuleData            []model.Rules
	RuleVersionSum      int //规则版本的汇总 通过这个来进行版本动态加载
	Host                model.Hosts
	PluginIpRateLimiter *plugin.IPRateLimiter //ip限流
	IPWhiteLists        []model.IPWhiteList   //ip 白名单
	UrlWhiteLists       []model.URLWhiteList  //url 白名单
	LdpUrlLists         []model.LDPUrl        //url 隐私保护

	IPBlockLists  []model.IPBlockList  //ip 黑名单
	UrlBlockLists []model.URLBlockList //url 黑名单
}
