package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore/loadbalance"
	"SamWaf/wafproxy"
	"SamWaf/webplugin"
	"context"
	"encoding/base64"
	"fmt"
	goahocorasick "github.com/samwafgo/ahocorasick"
	"golang.org/x/time/rate"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 加载全部host
func (waf *WafEngine) LoadAllHost() {
	//重新查询
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Find(&hosts)
	for i := 0; i < len(hosts); i++ {
		waf.LoadHost(hosts[i])
	}
}

// 加载指定host
func (waf *WafEngine) LoadHost(inHost model.Hosts) []innerbean.ServerRunTime {

	//检测https
	if inHost.Ssl == 1 {
		waf.AllCertificate.LoadSSL(inHost.Host, inHost.Certfile, inHost.Keyfile)
	}
	if inHost.GLOBAL_HOST == 1 {
		global.GWAF_GLOBAL_HOST_CODE = inHost.Code
	}
	onlineServer, ok := waf.ServerOnline[inHost.Port]
	if ok == false && inHost.GLOBAL_HOST == 0 {
		if inHost.START_STATUS == 0 {
			waf.ServerOnline[inHost.Port] = innerbean.ServerRunTime{
				ServerType: utils.GetServerByHosts(inHost),
				Port:       inHost.Port,
				Status:     1,
			}
		} else {
			delete(waf.ServerOnline, inHost.Port)
		}

	} else if ok {
		if (onlineServer.ServerType) == "https" && onlineServer.Svr != nil {

			zlog.Debug(strconv.Itoa(len(onlineServer.Svr.TLSConfig.Certificates)))
			/*onlineServer.Svr.TLSConfig.NameToCertificate = waf.AllCertificate[inHost.Port]
			onlineServer.Svr.TLSConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if x509Cert, ok := onlineServer.Svr.TLSConfig.NameToCertificate[clientInfo.ServerName]; ok {
					return x509Cert, nil
				}
				return nil, errors.New("config error")
			}*/
		}

	}
	//检查是否存在强制跳转HTTPS的情况
	if inHost.AutoJumpHTTPS == 1 {
		default80Port := 80
		_, ok := waf.ServerOnline[default80Port]
		if ok == false && inHost.GLOBAL_HOST == 0 {
			if inHost.START_STATUS == 0 {
				waf.ServerOnline[default80Port] = innerbean.ServerRunTime{
					ServerType: "http",
					Port:       default80Port,
					Status:     1,
				}
			} else {
				delete(waf.ServerOnline, default80Port)
			}
		}
	}
	//定义一个port int数组
	var ports = []int{}
	//如果存在一个主机绑定了多个Port的情况
	if inHost.BindMorePort != "" && inHost.GLOBAL_HOST == 0 {
		lines := strings.Split(inHost.BindMorePort, ",")
		for _, portStr := range lines {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil {
				continue
			}
			ports = append(ports, port)
			_, ok := waf.ServerOnline[port]
			if ok == false {
				if inHost.START_STATUS == 0 {
					if port == 443 {
						waf.ServerOnline[port] = innerbean.ServerRunTime{
							ServerType: "https",
							Port:       port,
							Status:     1,
						}
					} else {
						waf.ServerOnline[port] = innerbean.ServerRunTime{
							ServerType: "http",
							Port:       port,
							Status:     1,
						}
					}

				}
			}
		}
	}
	//加载主机对于的规则
	ruleHelper := &utils.RuleHelper{}
	ruleHelper.InitRuleEngine()
	//查询规则
	var vcnt int
	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("host_code = ? and rule_status<>999",
		inHost.Code).Select("sum(rule_version) as vcnt").Row().Scan(&vcnt)
	zlog.Debug("主机host" + inHost.Code + " 版本" + strconv.Itoa(vcnt))
	var ruleconfigs []model.Rules
	if vcnt > 0 {
		global.GWAF_LOCAL_DB.Where("host_code = ?and rule_status<>999", inHost.Code).Find(&ruleconfigs)
		ruleHelper.LoadRules(ruleconfigs)
	}
	//查询ip限流(应该针对一个网址只有一个)
	var anticcBean model.AntiCC

	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Limit(1).Find(&anticcBean)

	//初始化插件-ip计数器
	var pluginIpRateLimiter *webplugin.IPRateLimiter
	if anticcBean.Id != "" {
		// 根据配置选择限流模式
		if anticcBean.LimitMode == "window" {
			// 使用滑动窗口模式
			pluginIpRateLimiter = webplugin.NewWindowIPRateLimiter(anticcBean.Rate, anticcBean.Limit)
			zlog.Debug(fmt.Sprintf("初始化CC防护(滑动窗口模式) 主机%v 时间窗口(秒)%v 最大请求数%v",
				inHost.Host, anticcBean.Rate, anticcBean.Limit))
		} else {
			// 使用平均速率模式(默认)
			ratePerSecond := rate.Limit(float64(anticcBean.Limit) / float64(anticcBean.Rate))
			pluginIpRateLimiter = webplugin.NewIPRateLimiter(ratePerSecond, anticcBean.Limit)
			zlog.Debug(fmt.Sprintf("初始化CC防护(平均速率模式) 主机%v 时间窗口(秒)%v 最大请求数%v 每秒速率%v",
				inHost.Host, anticcBean.Rate, anticcBean.Limit, float64(anticcBean.Limit)/float64(anticcBean.Rate)))
		}
	}

	//查询ip白名单
	var ipwhitelist []model.IPAllowList
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&ipwhitelist)

	//查询url白名单
	var urlwhitelist []model.URLAllowList
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&urlwhitelist)

	//查询ip黑名单
	var ipblocklist []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&ipblocklist)

	//查询url白名单
	var urlblocklist []model.URLBlockList
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&urlblocklist)

	//查询url隐私保护
	var ldpurls []model.LDPUrl
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&ldpurls)

	//查询负载均衡
	var loadBalanceList []model.LoadBalance
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Order("create_time asc").Find(&loadBalanceList)

	//查询HTTP AUTH
	var httpAuthList []model.HttpAuthBase
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&httpAuthList)

	//查询自定义拦截界面
	var blockingPageList []model.BlockingPage
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&blockingPageList)
	blockingPageMap := map[string]model.BlockingPage{}
	if len(blockingPageList) > 0 {
		for i := 0; i < len(blockingPageList); i++ {
			if blockingPageList[i].BlockingType == "not_match_website" {
				blockingPageMap["not_match_website"] = blockingPageList[i]
			} else if blockingPageList[i].BlockingType == "other_block" {
				blockingPageMap["other_block"] = blockingPageList[i]
			}
		}
	}
	//查询缓存规则
	var cacheRuleList []model.CacheRule
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&cacheRuleList)

	//初始化主机host
	hostsafe := &wafenginmodel.HostSafe{
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{
			CurrentProxyIndex:       0,
			RevProxies:              []*wafproxy.ReverseProxy{},
			WeightRoundRobinBalance: loadbalance.NewWeightRoundRobinBalance(inHost.Code),
			IpHashBalance:           loadbalance.NewConsistentHashBalance(nil, inHost.Code),
		},
		LoadBalanceLists:    loadBalanceList,
		Rule:                ruleHelper,
		TargetHost:          inHost.Remote_host + ":" + strconv.Itoa(inHost.Remote_port),
		RuleData:            ruleconfigs,
		RuleVersionSum:      vcnt,
		Host:                inHost,
		PluginIpRateLimiter: pluginIpRateLimiter,
		IPWhiteLists:        ipwhitelist,
		UrlWhiteLists:       urlwhitelist,
		LdpUrlLists:         ldpurls,
		IPBlockLists:        ipblocklist,
		UrlBlockLists:       urlblocklist,
		AntiCCBean:          anticcBean,
		HttpAuthBases:       httpAuthList,
		BlockingPage:        blockingPageMap,
		CacheRule:           cacheRuleList,
	}
	hostsafe.Mux.Lock()
	defer hostsafe.Mux.Unlock()
	//目标关系情况
	waf.HostTarget[inHost.Host+":"+strconv.Itoa(inHost.Port)] = hostsafe
	//赋值到对照表里面
	waf.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(inHost.Port)

	if len(ports) > 0 {
		for _, port := range ports {
			//目标关系情况
			waf.HostTarget[inHost.Host+":"+strconv.Itoa(port)] = hostsafe
			//赋值到对照表里面
			waf.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(port)
		}
	}

	//如果存在强制跳转
	if inHost.AutoJumpHTTPS == 1 {
		waf.HostTarget[inHost.Host+":80"] = hostsafe
		waf.HostCode[inHost.Code] = inHost.Host + ":80"
	}
	//如果是不限制端口的情况
	if inHost.UnrestrictedPort == 1 {
		zlog.Debug("来源端口宽松模式")
		waf.HostTargetNoPort[inHost.Host] = inHost.Host + ":" + strconv.Itoa(inHost.Port)
	} else {
		if _, ok := waf.HostTargetNoPort[inHost.Host]; ok {
			zlog.Debug("来源端口严苛模式")
			delete(waf.HostTargetNoPort, inHost.Host)
		}

	}
	//如果存在一个主机绑定了多个域名的情况
	if inHost.BindMoreHost != "" {
		lines := strings.Split(inHost.BindMoreHost, "\n")
		for _, line := range lines {
			waf.HostTargetMoreDomain[line+":"+strconv.Itoa(inHost.Port)] = inHost.Code
		}
	}

	var serverOnlines = []innerbean.ServerRunTime{}
	serverOnlines = append(serverOnlines, waf.ServerOnline[inHost.Port])
	for _, port := range ports {
		_, ok := waf.ServerOnline[port]
		if ok == true {
			serverOnlines = append(serverOnlines, waf.ServerOnline[port])
		}
	}
	return serverOnlines
}

// RemovePortServer 检测如果没有端口在占用了，可以关闭相应端口
func (waf *WafEngine) RemovePortServer() {
	for onlinePort := range waf.ServerOnline {
		if waf_service.WafHostServiceApp.CheckAvailablePortExistApi(onlinePort) == 0 {
			//暂停服务 并 移除服务信息
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, svrOk := waf.ServerOnline[onlinePort]
			if svrOk {
				err := waf.ServerOnline[onlinePort].Svr.Shutdown(ctx)
				if err != nil {
					zlog.Error("shutting down: " + err.Error())
				} else {
					zlog.Info("shutdown processed successfully port" + strconv.Itoa(onlinePort))
				}
				delete(waf.ServerOnline, onlinePort)
			}
		}
	}
}

// RemoveHost 移除主机相关信息
func (waf *WafEngine) RemoveHost(host model.Hosts) {

	// 移除当前信息
	//a.移除对照关系
	delete(waf.HostCode, host.Code)
	//b.移除主机保护信息
	delete(waf.HostTarget, host.Host+":"+strconv.Itoa(host.Port))
	//c.移除某个端口下的证书数据
	waf.AllCertificate.RemoveSSL(host.Host)
	//d.删除更多内容里面域名信息
	for moreHost, hostCode := range waf.HostTargetMoreDomain {
		if hostCode == host.Code {
			delete(waf.HostTargetMoreDomain, moreHost)
		}
	}
	//检测如果端口已经没有关联服务就直接关闭掉
	waf.RemovePortServer()
}

// ReLoadSensitive 加载敏感词
func (waf *WafEngine) ReLoadSensitive() {
	//敏感词处理
	var sensitiveList []model.Sensitive
	global.GWAF_LOCAL_DB.Find(&sensitiveList)
	//敏感词
	waf.Sensitive = sensitiveList
	if len(sensitiveList) == 0 {
		return
	}
	// 提取 content 字段并转换为 [][]rune
	var keywords [][]rune
	var customData map[string]interface{}
	customData = make(map[string]interface{})
	for _, sensitive := range waf.Sensitive {
		keywords = append(keywords, []rune(sensitive.Content))
		customData[sensitive.Content] = sensitive
	}

	m := new(goahocorasick.Machine)
	err := m.BuildByCustom(keywords, customData)
	if err != nil {
		zlog.Error("load sensitive error", err)
		return
	}
	waf.SensitiveManager = m

}

// CheckRequestSensitive 检查是否需要请求敏感词检测
func (waf *WafEngine) CheckRequestSensitive() bool {
	var bean model.Sensitive
	//只要不是检测返回的，那说明是检查请求的
	global.GWAF_LOCAL_DB.Where("check_direction!=?", "out").Find(&bean).Limit(1)
	if len(bean.Id) > 0 {
		return true
	} else {
		return false
	}
}

// CheckResponseSensitive 检查是否需要响应敏感词检测
func (waf *WafEngine) CheckResponseSensitive() bool {
	var bean model.Sensitive
	//只要不是检测请求的，那说明是检查返回的
	global.GWAF_LOCAL_DB.Where("check_direction!=?", "in").Find(&bean).Limit(1)
	if len(bean.Id) > 0 {
		return true
	} else {
		return false
	}
}

// DoHttpAuthBase Http auth base 检测
func (waf *WafEngine) DoHttpAuthBase(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request) (bool, string) {
	isStop := false

	// 获取 Authorization 头部
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		tip := "当前网站需要授权方可访问"
		// 如果没有 Authorization 头部，返回 401
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, tip, http.StatusUnauthorized)
		isStop = true
		return isStop, tip
	}

	// 验证 Authorization 头部格式
	// "Basic base64(username:password)"
	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		tip := "密码格式不正确 Invalid authorization header format"
		http.Error(w, tip, http.StatusBadRequest)
		isStop = true
		return isStop, tip
	}

	// 解码 base64 编码的用户名和密码
	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		tip := "Invalid base64 encoding"
		http.Error(w, tip, http.StatusBadRequest)
		isStop = true
		return isStop, tip
	}

	// 解码后的结果是 "username:password"
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		tip := "密码格式不正确 Invalid authorization format"
		http.Error(w, tip, http.StatusBadRequest)
		isStop = true
		return isStop, tip
	}

	// 校验用户名和密码
	username, password := credentials[0], credentials[1]
	if !waf.checkCredentials(hostSafe, username, password) {
		tip := "密码错误"
		// 如果验证失败，返回 401
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, tip, http.StatusUnauthorized)
		isStop = true
		return isStop, tip
	}

	return isStop, ""
}

// checkCredentials 验证用户名和密码
func (waf *WafEngine) checkCredentials(hostSafe *wafenginmodel.HostSafe, username, password string) bool {
	// 这里硬编码了一个用户名和密码，实际使用中可以替换成数据库验证或其他方式
	baseList := hostSafe.HttpAuthBases
	if baseList == nil || len(baseList) == 0 {
		return false
	}
	for _, bean := range baseList {
		if bean.UserName == username && bean.Password == password {
			return true
		}
	}
	return false
}
