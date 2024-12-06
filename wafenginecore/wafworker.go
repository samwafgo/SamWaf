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
	goahocorasick "github.com/anknown/ahocorasick"
	"golang.org/x/time/rate"
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
func (waf *WafEngine) LoadHost(inHost model.Hosts) innerbean.ServerRunTime {

	//检测https
	if inHost.Ssl == 1 {
		/*dirPath := filepath.Join(utils.GetCurrentDir(), "ssl", "host", inHost.Id)
		// 检查目录是否存在
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			// 创建目录
			err := os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				zlog.Error("failed to create directory:", err.Error())
			}
		}
		keyFilePath := filepath.Join(dirPath, "domain.key")
		certFilePath := filepath.Join(dirPath, "domain.crt")

		// 检查 key 文件
		if err := utils.UpdateFileIsHasNewInfo(keyFilePath, inHost.Keyfile); err != nil {
			zlog.Error("failed to write key file: ", err.Error())
		}

		// 检查 cert 文件
		if err := utils.UpdateFileIsHasNewInfo(certFilePath, inHost.Certfile); err != nil {
			zlog.Error("failed to write key file: ", err.Error())
		}
		//waf.AllCertificate.LoadSSLByFilePath(inHost.Host, certFilePath, keyFilePath)
		*/
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
		pluginIpRateLimiter = webplugin.NewIPRateLimiter(rate.Limit(anticcBean.Rate), anticcBean.Limit)
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
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&loadBalanceList)
	//初始化主机host
	hostsafe := &wafenginmodel.HostSafe{
		LoadBalanceRuntime: &wafenginmodel.LoadBalanceRuntime{
			CurrentProxyIndex:       0,
			RevProxies:              []*wafproxy.ReverseProxy{},
			WeightRoundRobinBalance: &loadbalance.WeightRoundRobinBalance{},
			IpHashBalance:           loadbalance.NewConsistentHashBalance(nil),
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
	}
	hostsafe.Mux.Lock()
	defer hostsafe.Mux.Unlock()
	//目标关系情况
	waf.HostTarget[inHost.Host+":"+strconv.Itoa(inHost.Port)] = hostsafe
	//赋值到对照表里面
	waf.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(inHost.Port)

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

	return waf.ServerOnline[inHost.Port]
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
	for _, sensitive := range waf.Sensitive {
		// 将 content 转换为 []rune 并追加到 keywords
		keywords = append(keywords, []rune(sensitive.Content))
	}

	m := new(goahocorasick.Machine)
	err := m.Build(keywords)
	if err != nil {
		zlog.Error("load sensitive error", err)
		return
	}
	waf.SensitiveManager = m

}
