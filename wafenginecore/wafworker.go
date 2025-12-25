package wafenginecore

import (
	"SamWaf/common/uuid"
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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	goahocorasick "github.com/samwafgo/ahocorasick"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
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
		// 为主域名加载证书
		waf.AllCertificate.LoadSSL(inHost.Host, inHost.Certfile, inHost.Keyfile)

		// 为绑定的多个域名也加载相同的证书
		if inHost.BindMoreHost != "" {
			lines := strings.Split(inHost.BindMoreHost, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					waf.AllCertificate.LoadSSL(line, inHost.Certfile, inHost.Keyfile)
				}
			}
		}
	}
	if inHost.GLOBAL_HOST == 1 {
		global.GWAF_GLOBAL_HOST_CODE = inHost.Code
	}
	onlineServer, ok := waf.ServerOnline.Get(inHost.Port)
	if ok == false && inHost.GLOBAL_HOST == 0 {
		if inHost.START_STATUS == 0 {
			waf.ServerOnline.Set(inHost.Port, innerbean.ServerRunTime{
				ServerType: utils.GetServerByHosts(inHost),
				Port:       inHost.Port,
				Status:     1,
			})
		} else {
			waf.ServerOnline.Delete(inHost.Port)
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
		_, ok := waf.ServerOnline.Get(default80Port)
		if ok == false && inHost.GLOBAL_HOST == 0 {
			if inHost.START_STATUS == 0 {
				waf.ServerOnline.Set(default80Port, innerbean.ServerRunTime{
					ServerType: "http",
					Port:       default80Port,
					Status:     1,
				})
			} else {
				waf.ServerOnline.Delete(default80Port)
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
			_, ok := waf.ServerOnline.Get(port)
			if ok == false {
				if inHost.START_STATUS == 0 {
					if port == 443 {
						waf.ServerOnline.Set(port, innerbean.ServerRunTime{
							ServerType: "https",
							Port:       port,
							Status:     1,
						})
					} else {
						waf.ServerOnline.Set(port, innerbean.ServerRunTime{
							ServerType: "http",
							Port:       port,
							Status:     1,
						})
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
		if anticcBean.IsEnableRule {
			pluginIpRateLimiter.Rule = &utils.RuleHelper{}
			pluginIpRateLimiter.Rule.InitRuleEngine()
			pluginIpRateLimiter.Rule.LoadRuleString(anticcBean.RuleContent)
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
				// 域名不匹配使用固定的key
				blockingPageMap["not_match_website"] = blockingPageList[i]
			} else if blockingPageList[i].BlockingType == "other_block" {
				// other_block 类型根据 response_code 区分不同的错误页面
				// 例如: 403(WAF拦截), 404, 500, 502 等
				if blockingPageList[i].ResponseCode != "" {
					blockingPageMap[blockingPageList[i].ResponseCode] = blockingPageList[i]
				}
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
	serverOnline, isExist := waf.ServerOnline.Get(inHost.Port)
	if isExist {
		serverOnlines = append(serverOnlines, serverOnline)
	}
	for _, port := range ports {
		serverOnline, isExist := waf.ServerOnline.Get(port)
		if isExist {
			serverOnlines = append(serverOnlines, serverOnline)
		}
	}
	return serverOnlines
}

// RemovePortServer 检测如果没有端口在占用了，可以关闭相应端口
func (waf *WafEngine) RemovePortServer() {
	// 使用Range方法安全地遍历ServerOnline
	portsToRemove := make([]int, 0)

	waf.ServerOnline.Range(func(onlinePort int, serverRuntime innerbean.ServerRunTime) bool {
		if waf_service.WafHostServiceApp.CheckAvailablePortExistApi(onlinePort) == 0 {
			//暂停服务 并 移除服务信息
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if serverRuntime.Svr != nil {
				err := serverRuntime.Svr.Shutdown(ctx)
				if err != nil {
					zlog.Error("shutting down: " + err.Error())
				} else {
					zlog.Info("shutdown processed successfully port" + strconv.Itoa(onlinePort))
				}
			}
			// 记录需要删除的端口
			portsToRemove = append(portsToRemove, onlinePort)
		}
		return true // 继续遍历
	})

	// 删除已关闭的端口
	for _, port := range portsToRemove {
		waf.ServerOnline.Delete(port)
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

	// 移除绑定的多个域名的证书
	if host.BindMoreHost != "" {
		lines := strings.Split(host.BindMoreHost, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				waf.AllCertificate.RemoveSSL(line)
			}
		}
	}

	//d.删除更多内容里面域名信息
	for moreHost, hostCode := range waf.HostTargetMoreDomain {
		if hostCode == host.Code {
			delete(waf.HostTargetMoreDomain, moreHost)
		}
	}
	// 清理与该主机及后端绑定的 Transport 缓存
	waf.purgeTransportForHost(host)
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

	// 初始化敏感词检测方向映射
	if waf.SensitiveDirectionMap == nil {
		waf.SensitiveDirectionMap = make(map[string]bool)
	}
	// 重置映射
	waf.SensitiveDirectionMap["in"] = false
	waf.SensitiveDirectionMap["out"] = false
	waf.SensitiveDirectionMap["all"] = false

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
		if sensitive.CheckDirection == "in" && waf.SensitiveDirectionMap["in"] == false {
			// 检测请求
			waf.SensitiveDirectionMap["in"] = true
		} else if sensitive.CheckDirection == "out" && waf.SensitiveDirectionMap["out"] == false {
			// 检测响应
			waf.SensitiveDirectionMap["out"] = true
		} else if sensitive.CheckDirection == "all" && waf.SensitiveDirectionMap["all"] == false {
			// 检测请求和响应
			waf.SensitiveDirectionMap["all"] = true
		}
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
	// 优先使用预先计算的映射进行快速判断
	if waf.SensitiveDirectionMap != nil {
		// 检查是否有针对请求的敏感词检测
		return waf.SensitiveDirectionMap["in"] || waf.SensitiveDirectionMap["all"]
	}
	// 如果内存中没有数据，则进行数据库查询
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
	// 优先使用预先计算的映射进行快速判断
	if waf.SensitiveDirectionMap != nil {
		// 检查是否有针对响应的敏感词检测
		return waf.SensitiveDirectionMap["out"] || waf.SensitiveDirectionMap["all"]
	}

	// 如果内存中没有数据，则进行数据库查询
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

	// 获取认证类型，默认为 authorization（Basic Auth）
	authType := hostSafe.Host.HttpAuthBaseType
	if authType == "" {
		authType = "authorization"
	}

	// 根据认证类型选择不同的认证方式
	if authType == "authorization" {
		// 使用Basic Auth方式
		return waf.doBasicAuth(hostSafe, w, r)
	} else if authType == "custom" {
		// 使用自定义页面方式
		return waf.doCustomAuth(hostSafe, w, r)
	}

	return isStop, ""
}

// doBasicAuth 使用Basic Auth方式认证（原有逻辑）
func (waf *WafEngine) doBasicAuth(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request) (bool, string) {
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

// doCustomAuth 使用自定义页面方式认证
func (waf *WafEngine) doCustomAuth(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request) (bool, string) {
	// 处理登录页面的静态资源请求
	if strings.HasPrefix(r.URL.Path, "/samwaf_httpauth/") {
		waf.handleHttpAuthRequest(hostSafe, w, r)
		return true, "处理HTTP Auth请求"
	}

	// 检查是否已经通过认证
	clientIP := utils.GetSourceClientIP(r.RemoteAddr)

	// 尝试从Cookie中获取认证令牌
	cookie, err := r.Cookie("samwaf_httpauth_token")
	if err == nil && cookie.Value != "" {
		// 验证令牌是否有效
		cacheKey := "httpauth_pass:" + cookie.Value + ":" + clientIP
		val := global.GCACHE_WAFCACHE.Get(cacheKey)
		if val != nil && val == "ok" {
			// 认证有效，允许访问
			return false, ""
		}
	}

	// 未通过认证，显示登录页面
	tip := "需要登录认证"
	waf.serveLoginPage(w, r)
	return true, tip
}

// handleHttpAuthRequest 处理HTTP Auth相关请求
func (waf *WafEngine) handleHttpAuthRequest(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/samwaf_httpauth/")

	// 处理验证接口
	if path == "validate" && r.Method == "POST" {
		waf.handleHttpAuthValidate(hostSafe, w, r)
		return
	}

	// 处理静态文件（暂不需要，因为登录页面是独立的HTML）
	http.NotFound(w, r)
}

// handleHttpAuthValidate 处理登录验证
func (waf *WafEngine) handleHttpAuthValidate(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request) {
	clientIP := utils.GetSourceClientIP(r.RemoteAddr)

	// 安全策略：检查IP是否被锁定
	lockKey := "httpauth_lock:" + clientIP
	lockVal := global.GCACHE_WAFCACHE.Get(lockKey)
	if lockVal != nil {
		// IP已被锁定
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"success": false, "message": "登录失败次数过多，请3分钟后再试"}`))
		zlog.Warn("HTTP Auth登录IP被锁定", zap.String("ip", clientIP))
		return
	}

	// 解析请求体
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		zlog.Error("解析登录请求失败", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "message": "请求格式错误"}`))
		return
	}

	// 验证用户名和密码
	if !waf.checkCredentials(hostSafe, req.Username, req.Password) {
		// 验证失败，记录失败次数
		failCountKey := "httpauth_fail:" + clientIP
		failCount := 0

		if val := global.GCACHE_WAFCACHE.Get(failCountKey); val != nil {
			if count, ok := val.(int); ok {
				failCount = count
			}
		}

		failCount++
		zlog.Warn("HTTP Auth登录失败",
			zap.String("ip", clientIP),
			zap.String("username", req.Username),
			zap.Int("fail_count", failCount))

		// 失败次数超过10次，锁定IP 3分钟
		if failCount >= 10 {
			global.GCACHE_WAFCACHE.SetWithTTl(lockKey, "locked", 3*time.Minute)
			// 清除失败计数
			global.GCACHE_WAFCACHE.Remove(failCountKey)

			zlog.Error("HTTP Auth登录失败次数过多，锁定IP",
				zap.String("ip", clientIP),
				zap.Int("fail_count", failCount))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"success": false, "message": "登录失败次数过多，已锁定3分钟"}`))
			return
		}

		// 记录失败次数，5分钟内有效
		global.GCACHE_WAFCACHE.SetWithTTl(failCountKey, failCount, 5*time.Minute)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(`{"success": false, "message": "用户名或密码错误，剩余尝试次数：%d"}`, 10-failCount)))
		return
	}

	// 验证成功，清除失败计数
	failCountKey := "httpauth_fail:" + clientIP
	global.GCACHE_WAFCACHE.Remove(failCountKey)

	// 生成令牌
	authToken := uuid.GenUUID()

	zlog.Info("HTTP Auth登录成功",
		zap.String("ip", clientIP),
		zap.String("username", req.Username))

	// 将令牌存入缓存，默认24小时有效
	cacheKey := "httpauth_pass:" + authToken + ":" + clientIP
	global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, "ok", 24*time.Hour)

	// 设置Cookie
	cookie := &http.Cookie{
		Name:     "samwaf_httpauth_token",
		Value:    authToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   24 * 3600, // 24小时
	}
	http.SetCookie(w, cookie)

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success": true, "message": "登录成功", "redirect": "/"}`))
}

// serveLoginPage 提供登录页面
func (waf *WafEngine) serveLoginPage(w http.ResponseWriter, r *http.Request) {
	// 读取登录页面文件
	loginPagePath := utils.GetCurrentDir() + "/data/httpauth/login.html"

	// 检查文件是否存在
	if _, err := os.Stat(loginPagePath); os.IsNotExist(err) {
		zlog.Warn("登录页面文件不存在", zap.String("path", loginPagePath))
		http.Error(w, "登录页面未配置", http.StatusInternalServerError)
		return
	}

	// 读取文件内容
	content, err := os.ReadFile(loginPagePath)
	if err != nil {
		zlog.Error("读取登录页面失败", zap.Error(err))
		http.Error(w, "服务器错误", http.StatusInternalServerError)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
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

// purgeTransportForHost 清理指定主机相关的 TransportPool 键
func (waf *WafEngine) purgeTransportForHost(host model.Hosts) {
	// 构建需要匹配的 host:port 组合（主端口、80端口、绑定端口、绑定域名）
	hostStrs := map[string]bool{
		fmt.Sprintf("%s:%d", host.Host, host.Port): true,
	}
	if host.AutoJumpHTTPS == 1 {
		hostStrs[fmt.Sprintf("%s:%d", host.Host, 80)] = true
	}
	// BindMorePort 绑定的端口
	var morePorts []int
	if host.BindMorePort != "" && host.GLOBAL_HOST == 0 {
		lines := strings.Split(host.BindMorePort, ",")
		for _, portStr := range lines {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}
			if p, err := strconv.Atoi(portStr); err == nil {
				morePorts = append(morePorts, p)
				hostStrs[fmt.Sprintf("%s:%d", host.Host, p)] = true
			}
		}
	}
	// 绑定多域名
	if host.BindMoreHost != "" {
		lines := strings.Split(host.BindMoreHost, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// 绑定域名 + 主端口
			hostStrs[fmt.Sprintf("%s:%d", line, host.Port)] = true
			// 绑定域名 + 其他端口
			for _, p := range morePorts {
				hostStrs[fmt.Sprintf("%s:%d", line, p)] = true
			}
		}
	}

	// 扫描并删除匹配的 Transport 缓存
	waf.TransportMux.Lock()
	defer waf.TransportMux.Unlock()
	for key := range waf.TransportPool {
		parts := strings.Split(key, "_")
		if len(parts) != 5 {
			if t, ok := waf.TransportPool[key]; ok && t != nil {
				t.CloseIdleConnections()
			}
			delete(waf.TransportPool, key)
			continue
		}
		hostPart := parts[0]

		// 匹配 host：支持 hostPart 包含或不包含端口的情况
		matchHost := false
		// 1. 如果 hostPart 包含端口，直接匹配
		if _, exists := hostStrs[hostPart]; exists {
			matchHost = true
		} else {
			// 2. 如果 hostPart 不包含端口，检查 hostStrs 中是否有以 hostPart: 开头的项
			// 例如：hostPart = "example.com"，检查 hostStrs 中是否有 "example.com:80" 等
			for hostPortKey := range hostStrs {
				if strings.HasPrefix(hostPortKey, hostPart+":") {
					matchHost = true
					break
				}
			}
		}
		if matchHost {
			if t, ok := waf.TransportPool[key]; ok && t != nil {
				t.CloseIdleConnections()
			}
			delete(waf.TransportPool, key)
		}
	}
}
