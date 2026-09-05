package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore/loadbalance"
	"SamWaf/wafproxy"
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

	// 清理该 host 旧的 Transport 缓存，确保重载(尤其后端 IP/端口变化)时不复用过期连接池。
	// 原先由重载路径中的 RemoveHost 负责；现重载改为 LoadHost 原子替换、不再先 RemoveHost，故在此清理。
	waf.purgeTransportForHost(inHost)

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
	// 端口监听统一走 ResolveHostListens 唯一真源（issue #955）：显式 port_listens_json 优先，
	// 空值按老规则派生；主端口/副端口/AutoJumpHTTPS 隐式 80 不再各写一套判定。
	listens := utils.ResolveHostListens(inHost)
	//定义一个port int数组（需要注册域名路由的副端口，不含主端口与隐式80）
	var ports = []int{}
	for _, listen := range listens {
		if !listen.IsMain && !listen.Implied {
			ports = append(ports, listen.Port)
		}
		onlineServer, ok := waf.ServerOnline.Get(listen.Port)
		if !ok {
			if inHost.START_STATUS == 0 {
				waf.ServerOnline.Set(listen.Port, innerbean.ServerRunTime{
					ServerType: listen.Protocol,
					IPVersion:  listen.IPVersion,
					Port:       listen.Port,
					Status:     1,
				})
			}
		} else if inHost.START_STATUS == 0 {
			if onlineServer.ServerType != listen.Protocol {
				// 端口是全机共享资源：先加载者定协议，后到者协议不一致时保持先到先得，但必须发声
				waf.alertPortProtocolConflict(inHost, listen.Port, listen.Protocol, onlineServer.ServerType)
			} else if normalizeIPV(onlineServer.IPVersion) != normalizeIPV(listen.IPVersion) {
				// 已有监听不会按新 IP 版本自动重建，静默会让用户以为已生效
				waf.alertPortIPVersionPending(inHost, listen.Port, listen.IPVersion, onlineServer.IPVersion)
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
		global.GWAF_LOCAL_DB.Where("host_code = ? and rule_status<>999", inHost.Code).Find(&ruleconfigs)
		ruleHelper.LoadRules(ruleconfigs)
	}
	//查询ip限流(应该针对一个网址只有一个)
	var anticcBean model.AntiCC

	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Limit(1).Find(&anticcBean)

	//初始化插件-ip计数器（与热更新 ApplyAntiCCConfig 共用同一构造函数，避免两处算法不一致）
	pluginIpRateLimiter := BuildIPRateLimiter(anticcBean, inHost.Host)

	//加载并编译CC多规则（编译放在加载期，请求期只做取值与比较）
	ccRules := LoadCompiledCCRules(inHost.Code)

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

	//查询网页防篡改规则（含基线正文，供响应比对/回吐）
	var tamperRuleList []model.TamperRule
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Find(&tamperRuleList)

	//查询路径路由规则
	var pathRuleList []model.HostPathRule
	global.GWAF_LOCAL_DB.Where("host_code=? ", inHost.Code).Order("priority asc, create_time asc").Find(&pathRuleList)

	//解析静态站点安全配置（供路径规则静态文件服务共享使用）
	var staticCfg model.StaticSiteConfig
	if inHost.StaticSiteJSON != "" {
		_ = json.Unmarshal([]byte(inHost.StaticSiteJSON), &staticCfg)
	}

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
		CCRules:             ccRules,
		IPWhiteLists:        ipwhitelist,
		IPWhiteIndex:        BuildIPAllowIndex(ipwhitelist),
		IPWhiteGroupCodes:   ExtractAllowGroupCodes(ipwhitelist),
		UrlWhiteLists:       urlwhitelist,
		LdpUrlLists:         ldpurls,
		IPBlockLists:        ipblocklist,
		IPBlockIndex:        BuildIPBlockIndex(ipblocklist),
		IPBlockGroupCodes:   ExtractBlockGroupCodes(ipblocklist),
		UrlBlockLists:       urlblocklist,
		AntiCCBean:          anticcBean,
		HttpAuthBases:       httpAuthList,
		BlockingPage:        blockingPageMap,
		CacheRule:           cacheRuleList,
		TamperRules:         tamperRuleList,
		PathRules:           pathRuleList,
		StaticConfig:        staticCfg,
	}
	// 路由表(RCU)：在 writeMu 下克隆当前快照→在副本上登记本 host→原子发布。
	waf.withWriteTable(func(nt *routingTable) {
		// 原子替换：先清掉该 host(按旧 HostSafe 指针)此前占用的所有 key，再装新 key。
		// 全程在克隆表上操作、单次 Store 发布——主端口 key 不会出现"短暂缺失"，
		// 因此重载(改端口/SSL/绑定域名等)期间不会再返回 403 Host forbidden。
		if oldKey, ok := nt.HostCode[inHost.Code]; ok {
			if oldHS := nt.HostTarget[oldKey]; oldHS != nil {
				for k, v := range nt.HostTarget {
					if v == oldHS {
						delete(nt.HostTarget, k)
					}
				}
			}
		}
		for k, v := range nt.HostTargetMoreDomain {
			if v == inHost.Code {
				delete(nt.HostTargetMoreDomain, k)
			}
		}
		//目标关系情况
		nt.HostTarget[inHost.Host+":"+strconv.Itoa(inHost.Port)] = hostsafe
		//赋值到对照表里面
		nt.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(inHost.Port)

		if len(ports) > 0 {
			for _, port := range ports {
				//目标关系情况
				nt.HostTarget[inHost.Host+":"+strconv.Itoa(port)] = hostsafe
				// 注意：HostCode[code] 始终指向主端口 key（已在上方赋值），不在此处覆盖
			}
		}

		//如果存在强制跳转
		if inHost.AutoJumpHTTPS == 1 {
			nt.HostTarget[inHost.Host+":80"] = hostsafe
			nt.HostCode[inHost.Code] = inHost.Host + ":80"
		}
		//如果是不限制端口的情况
		if inHost.UnrestrictedPort == 1 {
			zlog.Debug("来源端口宽松模式")
			nt.HostTargetNoPort[inHost.Host] = inHost.Host + ":" + strconv.Itoa(inHost.Port)
			// 多域名也注册到宽松端口映射
			if inHost.BindMoreHost != "" {
				for _, moreLine := range strings.Split(inHost.BindMoreHost, "\n") {
					moreLine = strings.TrimSpace(moreLine)
					if moreLine != "" {
						nt.HostTargetNoPort[moreLine] = inHost.Host + ":" + strconv.Itoa(inHost.Port)
					}
				}
			}
		} else {
			if _, ok := nt.HostTargetNoPort[inHost.Host]; ok {
				zlog.Debug("来源端口严苛模式")
				delete(nt.HostTargetNoPort, inHost.Host)
			}
			// 多域名也从宽松端口映射中移除
			if inHost.BindMoreHost != "" {
				for _, moreLine := range strings.Split(inHost.BindMoreHost, "\n") {
					moreLine = strings.TrimSpace(moreLine)
					if moreLine != "" {
						delete(nt.HostTargetNoPort, moreLine)
					}
				}
			}
		}
		//如果存在一个主机绑定了多个域名的情况
		if inHost.BindMoreHost != "" {
			lines := strings.Split(inHost.BindMoreHost, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// 主端口
				nt.HostTargetMoreDomain[line+":"+strconv.Itoa(inHost.Port)] = inHost.Code
				// 副端口（BindMorePort）也需要注册，否则副域名+副端口无法路由
				for _, extraPort := range ports {
					nt.HostTargetMoreDomain[line+":"+strconv.Itoa(extraPort)] = inHost.Code
				}
			}
		}
	})

	// 返回本站全部监听 runtime（含 AutoJumpHTTPS 隐式 80），供"新增站点"路径逐个启动
	var serverOnlines = []innerbean.ServerRunTime{}
	for _, listen := range listens {
		serverOnline, isExist := waf.ServerOnline.Get(listen.Port)
		if isExist {
			serverOnlines = append(serverOnlines, serverOnline)
		}
	}
	return serverOnlines
}

func normalizeIPV(ipv string) string {
	if ipv == "" {
		return utils.ListenIPVBoth
	}
	return ipv
}

// alertPortProtocolConflict 端口协议冲突发声：系统日志 + WebSocket 推送（issue #955 的静默点）。
// 引擎不因冲突拒绝启动，先到先得维持现状，由用户依提示处理。
func (waf *WafEngine) alertPortProtocolConflict(inHost model.Hosts, port int, wantProto, activeProto string) {
	msg := fmt.Sprintf("端口协议冲突：站点 %s 声明端口 %d 为 %s，但该端口当前按 %s 监听（先加载者生效）。若是多个网站对同一端口声明了不同协议，请统一协议或更换端口；若是您刚修改了本站该端口的协议，需重启引擎（或重启程序）后生效",
		inHost.Host, port, strings.ToUpper(wantProto), strings.ToUpper(activeProto))
	zlog.Warn(msg)
	global.GQEQUE_LOG_DB.Enqueue(&model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "系统运行错误",
		OpContent: msg,
	})
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
		Msg:             msg,
		Success:         "false",
	})
}

// alertPortIPVersionPending IP 版本变更未生效发声：已有监听不按新 ipv 自动重建，需重启引擎
func (waf *WafEngine) alertPortIPVersionPending(inHost model.Hosts, port int, wantIPV, activeIPV string) {
	msg := fmt.Sprintf("端口 %d 当前按 IP版本 %s 监听，站点 %s 本次声明为 %s：已有监听不会自动重建，需重启引擎（或重启程序）后生效",
		port, normalizeIPV(activeIPV), inHost.Host, normalizeIPV(wantIPV))
	zlog.Warn(msg)
	global.GQEQUE_LOG_DB.Enqueue(&model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "信息",
		OpContent: msg,
	})
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
		Msg:             msg,
		Success:         "false",
	})
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

			// 先停 HTTP/3：老代码只关了 Svr、从不碰 H3，删掉 map 条目后 UDP socket 就彻底泄漏了(issue #916)
			if serverRuntime.H3 != nil {
				waf.stopHTTP3(onlinePort, serverRuntime.H3)
			}
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

	// 移除当前信息：路由表(RCU)在 writeMu 下克隆→在副本上删除本 host 相关条目→原子发布。
	waf.withWriteTable(func(nt *routingTable) {
		//a.移除对照关系
		delete(nt.HostCode, host.Code)
		//b.移除主机保护信息：主端口/副端口/AutoJumpHTTPS 的 80 统一按监听表清理，避免残留 stale 指针
		delete(nt.HostTarget, host.Host+":"+strconv.Itoa(host.Port))
		for _, listen := range utils.ResolveHostListens(host) {
			delete(nt.HostTarget, host.Host+":"+strconv.Itoa(listen.Port))
		}
		//b4.移除 HostTargetNoPort 中的主域名和多域名条目
		delete(nt.HostTargetNoPort, host.Host)
		if host.BindMoreHost != "" {
			for _, moreLine := range strings.Split(host.BindMoreHost, "\n") {
				moreLine = strings.TrimSpace(moreLine)
				if moreLine != "" {
					delete(nt.HostTargetNoPort, moreLine)
				}
			}
		}
		//d.删除更多内容里面域名信息
		for moreHost, hostCode := range nt.HostTargetMoreDomain {
			if hostCode == host.Code {
				delete(nt.HostTargetMoreDomain, moreHost)
			}
		}
	})

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
		if len(sensitive.Content) == 0 {
			// ahocorasick 不支持空字符串模式，跳过以避免 index out of range [-1] panic
			continue
		}
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

	if len(keywords) == 0 {
		return
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
//
// clientIP 由调用方按站点「真实IP来源」解析后传入，与访问日志的 SRC_IP 同源。
// 认证链路自己再取一次连接 IP 的话，站点挂在 CDN／前置 Nginx 后面时会话列表里
// 全站都是同一个边缘节点地址，「绑定登录 IP」这条约束也会一并失效。
func (waf *WafEngine) DoHttpAuthBase(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request, clientIP string) (bool, string) {
	cfg := model.DecodeHttpAuthConfig(hostSafe.Host.HttpAuthJSON)
	if hostSafe.Host.HttpAuthBaseType == model.HttpAuthTypeCustom {
		return waf.doCustomAuth(hostSafe, w, r, clientIP, cfg)
	}
	// 空值(存量站点)与未知取值都按 Basic 走：开关已经开了，认不出类型就放行等于这道门形同虚设
	return waf.doBasicAuth(hostSafe, w, r, clientIP, cfg)
}

// writeBasicChallenge 发 401 并要求浏览器输入密码。
//
// nonce 非空时 realm 会跟着变——浏览器按 realm 缓存凭证，realm 不变就只会拿旧凭证
// 自动重试，用户永远看不到弹窗。这是 Basic 模式下让「踢下线/到期」生效的唯一手段。
func (waf *WafEngine) writeBasicChallenge(w http.ResponseWriter, nonce, tip string) {
	realm := "Restricted"
	if nonce != "" {
		realm = "Restricted-" + nonce
	}
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+realm+"\"")
	http.Error(w, tip, http.StatusUnauthorized)
}

// cutAuditName 截断用户名。用户名来自请求头或登录表单，是攻击者可控的任意长度字符串，
// 直接入库会撞 account_name 的列宽。
//
// 按字节切完还要过一次 ToValidUTF8：128 字节的边界可能落在一个多字节字符中间，
// 留下的半个字符会被 MySQL 的 utf8mb4 列拒收，那条审计记录就没了——
// 等于给了攻击者一个「用超长多字节用户名让自己的爆破不被记录」的口子。
func cutAuditName(name string) string {
	if len(name) <= 128 {
		return name
	}
	return strings.ToValidUTF8(name[:128], "")
}

// httpAuthAudit 组装一条网站密码访问的审计流水。
func (waf *WafEngine) httpAuthAudit(hostSafe *wafenginmodel.HostSafe, r *http.Request,
	clientIP, userName string) waf_service.AuditEntry {
	return waf_service.AuditEntry{
		AccountName: cutAuditName(userName),
		Host:        hostSafe.Host.Host,
		HostCode:    hostSafe.Host.Code,
		URL:         r.URL.Path, // 只记路径：查询串里可能带业务参数，审计表没有必要留
		ClientIP:    clientIP,
		UserAgent:   r.UserAgent(),
	}
}

// auditHttpAuthDenied 记一条「未登录被拦」。
// 这是本功能唯一的高频事件——一次目录扫描就是几千个未登录请求，必须走节流。
func (waf *WafEngine) auditHttpAuthDenied(hostSafe *wafenginmodel.HostSafe, r *http.Request, clientIP, msg string) {
	entry := waf.httpAuthAudit(hostSafe, r, clientIP, "")
	entry.Event = model.HttpAuthEventDenied
	entry.Result = model.AccessAuditFail
	entry.Message = msg
	waf_service.WafSecurityAuditServiceApp.WriteThrottled(entry)
}

// doBasicAuth 浏览器弹窗方式（HTTP Basic）
func (waf *WafEngine) doBasicAuth(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request,
	clientIP string, cfg model.HttpAuthConfig) (bool, string) {

	// 获取 Authorization 头部
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		tip := "当前网站需要授权方可访问"
		waf.writeBasicChallenge(w, "", tip)
		waf.auditHttpAuthDenied(hostSafe, r, clientIP, tip)
		return true, tip
	}

	// 验证 Authorization 头部格式 "Basic base64(username:password)"
	authParts := strings.SplitN(authHeader, " ", 2)
	if len(authParts) != 2 || authParts[0] != "Basic" {
		tip := "密码格式不正确 Invalid authorization header format"
		http.Error(w, tip, http.StatusBadRequest)
		return true, tip
	}

	// 解码 base64 编码的用户名和密码
	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		tip := "Invalid base64 encoding"
		http.Error(w, tip, http.StatusBadRequest)
		return true, tip
	}

	// 解码后的结果是 "username:password"
	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		tip := "密码格式不正确 Invalid authorization format"
		http.Error(w, tip, http.StatusBadRequest)
		return true, tip
	}

	// 校验用户名和密码
	username, password := credentials[0], credentials[1]
	if !waf.checkCredentials(hostSafe, username, password) {
		tip := "密码错误"
		waf.writeBasicChallenge(w, "", tip)
		// Basic 模式没有登录表单，爆破就是一串带头的普通请求，逐条记会把审计表刷爆，走节流
		entry := waf.httpAuthAudit(hostSafe, r, clientIP, username)
		entry.Event = model.HttpAuthEventLoginFail
		entry.Result = model.AccessAuditFail
		entry.Message = "网站密码错误"
		waf_service.WafSecurityAuditServiceApp.WriteThrottled(entry)
		return true, tip
	}

	// 凭证过关，接着做会话记账：到期或被踢时要换 realm 把浏览器重新逼回弹窗
	res := waf_service.WafHttpAuthSessionServiceApp.TouchBasicSession(hostSafe.Host, username,
		clientIP, r.UserAgent(), cfg)
	if res.Challenge {
		tip := "登录状态已失效，请重新输入密码"
		if res.Expired {
			tip = "登录已到期，请重新输入密码"
			entry := waf.httpAuthAudit(hostSafe, r, clientIP, username)
			entry.Event = model.HttpAuthEventExpired
			entry.Result = model.AccessAuditOK
			entry.Message = "网站密码会话到期，要求重新认证"
			waf_service.WafSecurityAuditServiceApp.WriteThrottled(entry)
		}
		waf.writeBasicChallenge(w, res.RealmNonce, tip)
		return true, tip
	}

	// 只有真正建了会话行才算一次登录：Basic 每个请求都带凭证，逐个请求记就是成百上千条
	if res.Created {
		entry := waf.httpAuthAudit(hostSafe, r, clientIP, username)
		entry.Event = model.HttpAuthEventLoginOK
		entry.Result = model.AccessAuditOK
		entry.Message = "网站密码登录成功(浏览器弹窗方式)"
		if res.Session != nil {
			entry.SessionCode = res.Session.TokenCode
		}
		waf_service.WafSecurityAuditServiceApp.Write(entry)
	}
	return false, ""
}

// doCustomAuth 自定义登录页方式
func (waf *WafEngine) doCustomAuth(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request,
	clientIP string, cfg model.HttpAuthConfig) (bool, string) {

	authPathPrefix := utils.GetHttpAuthPathOrDefault(hostSafe.Host.HttpAuthPathPrefix)

	// 处理登录页面自身的请求
	if strings.HasPrefix(r.URL.Path, authPathPrefix+"/") {
		waf.handleHttpAuthRequest(hostSafe, w, r, authPathPrefix, clientIP, cfg)
		return true, "处理HTTP Auth请求"
	}

	// 检查是否已经通过认证
	cookie, err := r.Cookie("samwaf_httpauth_token")
	if err == nil && cookie.Value != "" {
		if _, ok := waf_service.WafHttpAuthSessionServiceApp.ValidateCustom(hostSafe.Host.Code,
			cookie.Value, clientIP, cfg); ok {
			return false, ""
		}
	}

	// 未通过认证，显示登录页面
	tip := "需要登录认证"
	waf.auditHttpAuthDenied(hostSafe, r, clientIP, tip)
	waf.serveLoginPage(w, r, authPathPrefix)
	return true, tip
}

// handleHttpAuthRequest 处理HTTP Auth相关请求
func (waf *WafEngine) handleHttpAuthRequest(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request,
	pathPrefix, clientIP string, cfg model.HttpAuthConfig) {
	path := strings.TrimPrefix(r.URL.Path, pathPrefix+"/")

	// 处理验证接口
	if path == "validate" && r.Method == "POST" {
		waf.handleHttpAuthValidate(hostSafe, w, r, clientIP, cfg)
		return
	}

	// 处理静态文件（暂不需要，因为登录页面是独立的HTML）
	http.NotFound(w, r)
}

// handleHttpAuthValidate 处理登录验证
func (waf *WafEngine) handleHttpAuthValidate(hostSafe *wafenginmodel.HostSafe, w http.ResponseWriter, r *http.Request,
	clientIP string, cfg model.HttpAuthConfig) {

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

		if count, err := global.GCACHE_WAFCACHE.GetInt(failCountKey); err == nil {
			failCount = count
		}

		failCount++
		zlog.Warn("HTTP Auth登录失败",
			zap.String("ip", clientIP),
			zap.String("username", req.Username),
			zap.Int("fail_count", failCount))

		entry := waf.httpAuthAudit(hostSafe, r, clientIP, req.Username)
		entry.Result = model.AccessAuditFail

		// 失败次数超过10次，锁定IP 3分钟
		if failCount >= 10 {
			global.GCACHE_WAFCACHE.SetWithTTl(lockKey, "locked", 3*time.Minute)
			// 清除失败计数
			global.GCACHE_WAFCACHE.Remove(failCountKey)
			zlog.Error("HTTP Auth登录失败次数过多，锁定IP",
				zap.String("ip", clientIP),
				zap.Int("fail_count", failCount))

			entry.Event = model.HttpAuthEventLocked
			entry.Message = "网站密码连续输错10次，该IP已锁定3分钟"
			waf_service.WafSecurityAuditServiceApp.Write(entry)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"success": false, "message": "登录失败次数过多，已锁定3分钟"}`))
			return
		}

		// 记录失败次数，5分钟内有效
		global.GCACHE_WAFCACHE.SetWithTTl(failCountKey, failCount, 5*time.Minute)

		entry.Event = model.HttpAuthEventLoginFail
		entry.Message = fmt.Sprintf("网站密码错误，剩余尝试次数：%d", 10-failCount)
		waf_service.WafSecurityAuditServiceApp.Write(entry)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf(`{"success": false, "message": "用户名或密码错误，剩余尝试次数：%d"}`, 10-failCount)))
		return
	}

	// 验证成功，清除失败计数
	failCountKey := "httpauth_fail:" + clientIP
	global.GCACHE_WAFCACHE.Remove(failCountKey)

	// 建会话：明文令牌只出现在 Cookie 里，库与缓存存的都是它的 sha256
	authToken, sess, err := waf_service.WafHttpAuthSessionServiceApp.CreateCustomSession(hostSafe.Host,
		req.Username, clientIP, r.UserAgent(), cfg)
	if err != nil {
		zlog.Error("HTTP Auth建立会话失败", zap.Error(err))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "message": "服务器错误"}`))
		return
	}

	zlog.Info("HTTP Auth登录成功",
		zap.String("ip", clientIP),
		zap.String("username", req.Username))

	entry := waf.httpAuthAudit(hostSafe, r, clientIP, req.Username)
	entry.Event = model.HttpAuthEventLoginOK
	entry.Result = model.AccessAuditOK
	entry.SessionCode = sess.TokenCode
	entry.Message = "网站密码登录成功(自定义页面方式)"
	waf_service.WafSecurityAuditServiceApp.Write(entry)

	// 设置Cookie，有效期跟随站点配置的会话时长
	cookie := &http.Cookie{
		Name:     "samwaf_httpauth_token",
		Value:    authToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cfg.SessionTTL) * 60,
	}
	http.SetCookie(w, cookie)

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success": true, "message": "登录成功", "redirect": "/"}`))
}

// serveLoginPage 提供登录页面
func (waf *WafEngine) serveLoginPage(w http.ResponseWriter, r *http.Request, pathPrefix string) {
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

	// 替换路径前缀
	htmlStr := string(content)
	if pathPrefix == "" {
		pathPrefix = "/samwaf_httpauth"
	}
	htmlStr = strings.ReplaceAll(htmlStr, "/samwaf_httpauth/", pathPrefix+"/")
	htmlStr = strings.ReplaceAll(htmlStr, "'/samwaf_httpauth'", "'"+pathPrefix+"'")
	htmlStr = strings.ReplaceAll(htmlStr, "\"/samwaf_httpauth\"", "\""+pathPrefix+"\"")

	// 设置响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlStr))
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
	// 构建需要匹配的 host:port 组合（主端口、隐式80、副端口、绑定域名），端口来源统一走监听表
	hostStrs := map[string]bool{
		fmt.Sprintf("%s:%d", host.Host, host.Port): true,
	}
	var morePorts []int
	for _, listen := range utils.ResolveHostListens(host) {
		hostStrs[fmt.Sprintf("%s:%d", host.Host, listen.Port)] = true
		if !listen.IsMain && !listen.Implied {
			morePorts = append(morePorts, listen.Port)
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
