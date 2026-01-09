package wafenginecore

import (
	"SamWaf/common/domaintool"
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"SamWaf/wafenginecore/loadbalance"
	"SamWaf/wafenginecore/wafhttpcore"
	"SamWaf/wafenginecore/wafhttpserver"
	"SamWaf/wafenginecore/wafwebcache"
	"SamWaf/wafproxy"
	"SamWaf/webplugin"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go/http3"
	goahocorasick "github.com/samwafgo/ahocorasick"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type WafEngine struct {
	//主机情况（key:主机名+":"+端口,value : hostsafe信息里面有规则,ip信息等）
	HostTarget map[string]*wafenginmodel.HostSafe
	//主机和code的关系（key:主机code,value:主机名+":"+端口）
	HostCode map[string]string
	//主机域名和配置防护关系 (key:主机域名,value:主机的hostCode)
	HostTargetNoPort map[string]string
	//更多域名和配置防护关系 (key:主机域名,value:主机的hostCode)  一个主机绑定很多域名的情况
	HostTargetMoreDomain map[string]string
	//服务在线情况（key：端口，value :服务情况）
	ServerOnline *wafenginmodel.SafeServerMap

	AllCertificate      AllCertificate //所有证书
	EngineCurrentStatus int            // 当前waf引擎状态

	//敏感词管理
	Sensitive        []model.Sensitive //敏感词
	SensitiveManager *goahocorasick.Machine
	// 敏感词检测方向映射，用于快速判断是否需要存在
	SensitiveDirectionMap map[string]bool // key: "in"/"out"/"all", value: 是否存在

	TransportPool map[string]*http.Transport // 添加Transport缓存池
	TransportMux  sync.RWMutex               // 保护Transport池的读写锁

	// 插件管理器（避免循环导入）
	PluginManager interface{} // 使用 interface{} 避免导入 plugin/manager
}

func (waf *WafEngine) Error() string {
	fs := "HTTP: %d, HostCode: %d, Message: %s"
	zlog.Error(fmt.Sprintf(fs))
	return fmt.Sprintf(fs)
}

// inferAttackType 根据检测规则标题推断攻击类型
func inferAttackType(ruleTitle string) string {
	ruleTitle = strings.ToLower(ruleTitle)

	// CC攻击
	if strings.Contains(ruleTitle, "cc") || strings.Contains(ruleTitle, "频次") || strings.Contains(ruleTitle, "rate limit") {
		return "cc_attack"
	}

	// SQL注入
	if strings.Contains(ruleTitle, "sql") || strings.Contains(ruleTitle, "注入") {
		return "sql_injection"
	}

	// XSS攻击
	if strings.Contains(ruleTitle, "xss") || strings.Contains(ruleTitle, "跨站") {
		return "xss_attack"
	}

	// 扫描工具
	if strings.Contains(ruleTitle, "scan") || strings.Contains(ruleTitle, "扫描") {
		return "scan_tool"
	}

	// RCE远程代码执行
	if strings.Contains(ruleTitle, "rce") || strings.Contains(ruleTitle, "代码执行") || strings.Contains(ruleTitle, "命令执行") {
		return "rce_attack"
	}

	// 目录穿越
	if strings.Contains(ruleTitle, "traversal") || strings.Contains(ruleTitle, "穿越") || strings.Contains(ruleTitle, "目录") {
		return "dir_traversal"
	}

	// Bot爬虫
	if strings.Contains(ruleTitle, "bot") || strings.Contains(ruleTitle, "爬虫") {
		return "bot_attack"
	}

	// 敏感词
	if strings.Contains(ruleTitle, "sensitive") || strings.Contains(ruleTitle, "敏感词") {
		return "sensitive_word"
	}

	// IP黑名单
	if strings.Contains(ruleTitle, "ip") && (strings.Contains(ruleTitle, "黑名单") || strings.Contains(ruleTitle, "block") || strings.Contains(ruleTitle, "deny")) {
		return "ip_blocked"
	}

	// URL黑名单
	if strings.Contains(ruleTitle, "url") && (strings.Contains(ruleTitle, "黑名单") || strings.Contains(ruleTitle, "block") || strings.Contains(ruleTitle, "deny")) {
		return "url_blocked"
	}

	// 防盗链
	if strings.Contains(ruleTitle, "leech") || strings.Contains(ruleTitle, "防盗链") || strings.Contains(ruleTitle, "hotlink") {
		return "anti_leech"
	}

	// 自定义规则
	if strings.Contains(ruleTitle, "rule") || strings.Contains(ruleTitle, "规则") {
		return "custom_rule"
	}

	// OWASP规则
	if strings.Contains(ruleTitle, "owasp") {
		return "owasp_rule"
	}

	// 插件拦截
	if strings.Contains(ruleTitle, "plugin") || strings.Contains(ruleTitle, "插件") {
		return "plugin_block"
	}

	// 默认返回通用拦截类型
	return ""
}
func (waf *WafEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	innerLogName := "WafEngine ServeHTTP"
	global.IncrementQPS() // 使用统一的QPS增量函数

	port := ""
	host := r.Host
	if !strings.Contains(host, ":") {
		// 检查请求是否使用了HTTPS
		if r.TLS != nil {
			// 请求使用了HTTPS
			host = host + ":443"
		} else {
			// 请求使用了HTTP
			host = host + ":80"
		}
	}
	// 从 host 字符串中提取端口
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
	}
	defer func() {
		e := recover()
		if e != nil {
			// 检查是否是连接断开相关的错误
			if e == http.ErrAbortHandler {
				fmt.Printf("Client connection aborted: %s\n", r.URL.Path)
				return
			}
			// 其他类型的panic才打印详细堆栈
			fmt.Printf("Unexpected error in request handler: %v\n", e)
			debug.PrintStack()
		}
	}()
	targetCode := ""
	//检测是否是不检测端口的情况
	if targetHost, ok := waf.HostTargetNoPort[utils.GetPureDomain(host)]; ok {
		host = targetHost
	}
	findHost := false
	target, ok := waf.HostTarget[host]
	if !ok {
		// 看看是不是泛域名情况
		target, ok = waf.HostTarget[domaintool.MaskSubdomain(host)]
		if ok {
			findHost = true
			targetCode = target.Host.Code
		}
	} else {
		targetCode = target.Host.Code
		findHost = true
	}

	if !findHost {
		// 绑定更多域名的信息
		targetCode, ok = waf.HostTargetMoreDomain[host]
		if ok {
			findHost = true
		} else {
			// 看看是不是泛域名情况
			targetCode, ok = waf.HostTargetMoreDomain[domaintool.MaskSubdomain(host)]
			if ok {
				findHost = true
			}
		}
	}

	//检测是否是宽松端口且是不指定域名的情况
	if targetHost, ok := waf.HostTargetNoPort["*"]; ok {
		host = targetHost
		//检测是否存在不指定域名的情况
		target, ok = waf.HostTarget[host]
		if ok {
			findHost = true
			targetCode = target.Host.Code
			zlog.Debug(fmt.Sprintf("%s %s", innerLogName, "触发*逻辑和来源port"))
		}
	} else {
		//检测是否存在不指定域名的情况
		target, ok = waf.HostTarget["*:"+port]
		if ok {
			findHost = true
			targetCode = target.Host.Code
			zlog.Debug(fmt.Sprintf("%s %s", innerLogName, "触发*逻辑"))
		}
	}

	// 检查域名是否已经注册
	if findHost == true {
		hostTarget := waf.HostTarget[waf.HostCode[targetCode]]
		hostCode := hostTarget.Host.Code

		incrementMonitor(hostCode)
		defer decrementMonitor(hostCode)
		//检测网站是否已关闭
		if hostTarget.Host.START_STATUS == 1 {
			resBytes := []byte("<html><head><title>网站已关闭</title></head><body><center><h1>当前访问网站已关闭</h1> <br><h3></h3></center></body> </html>")

			w.WriteHeader(http.StatusServiceUnavailable)
			if _, writeErr := w.Write(resBytes); writeErr != nil {
				zlog.Debug("write fail:", zap.Any("err", writeErr))
				return
			}

			return
		}
		// 取出客户IP
		ipErr, clientIP, clientPort := waf.getClientIP(r, strings.Split(global.GCONFIG_RECORD_PROXY_HEADER, ",")...)
		if ipErr != nil {
			zlog.Error("get client error", ipErr.Error())
			return
		}
		_, ok := waf.ServerOnline.Get(hostTarget.Host.Remote_port)
		//检测如果访问IP和远程IP是同一个IP，且远程端口在本地Server已存在则显示配置错误
		if clientIP == hostTarget.Host.Remote_ip && ok == true {
			resBytes := []byte("500: 配置有误" + host + " 当前IP和访问远端IP一样，且端口也一样，会造成循环问题")
			_, err := w.Write(resBytes)
			if err != nil {
				zlog.Debug("write fail:", zap.Any("", err))
				return
			}
			return
		}

		// 静态站点服务检查
		staticSiteConfig := InitDefaultStaticSiteConfig()
		err := json.Unmarshal([]byte(hostTarget.Host.StaticSiteJSON), &staticSiteConfig)
		if err != nil {
			zlog.Debug("解析static site json失败")
		}

		//检测cache
		cacheConfig := model.CacheConfig{
			IsEnableCache:   0,
			CacheLocation:   "",
			CacheDir:        "",
			MaxFileSizeMB:   0,
			MaxMemorySizeMB: 0,
		}
		err = json.Unmarshal([]byte(hostTarget.Host.CacheJSON), &cacheConfig)
		if err != nil {
			zlog.Debug("解析cache json失败")
		}

		// 获取请求报文的内容长度
		contentLength := r.ContentLength
		var bodyByte []byte

		// 拷贝一份request的Body ,控制不记录大文件的情况
		if r.Body != nil && r.Body != http.NoBody && (contentLength < (global.GCONFIG_RECORD_MAX_BODY_LENGTH) || cacheConfig.IsEnableCache == 1) {
			// 检查请求是否包含Content-Encoding
			if r.Header.Get("Content-Encoding") != "" {
				// 处理压缩的请求体
				decompressedBytes, decompressErr := waf.decompressRequestContent(r)
				if decompressErr != nil {
					zlog.Warn("请求Content-Encoding处理失败: %v", decompressErr)
					// 如果解压失败，使用原始内容
					bodyByte, _ = io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
				} else {
					bodyByte = decompressedBytes
					// 请求体已经在decompressRequestContent中更新
				}
			} else {
				// 没有压缩，正常处理
				bodyByte, _ = io.ReadAll(r.Body)
				// 把刚刚读出来的再写进去，不然后面解析表单数据就解析不到了
				r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
			}
		}
		cookies, _ := json.Marshal(r.Cookies())

		hlen := 0
		for key, values := range r.Header {
			for _, value := range values {
				hlen += len(key)
				hlen += len(": ")
				hlen += len(value)
				hlen += len("\r\n")
			}
		}
		var Header strings.Builder
		Header.Grow(hlen)
		for key, values := range r.Header {
			for _, value := range values {
				Header.WriteString(key)
				Header.WriteString(": ")
				Header.WriteString(value)
				Header.WriteString("\r\n")
			}
		}
		header := Header.String()

		region := utils.GetCountry(clientIP)

		currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))

		//URL 解码
		deRawQueryUrl := wafhttpcore.WafHttpCoreUrlEncode(r.URL.RawQuery, 10)
		datetimeNow := time.Now()
		weblogbean := innerbean.WebLog{
			HOST:                 r.Host,
			URL:                  r.RequestURI,
			RawQuery:             deRawQueryUrl,
			REFERER:              r.Referer(),
			USER_AGENT:           r.UserAgent(),
			METHOD:               r.Method,
			HEADER:               header,
			COUNTRY:              region[0],
			PROVINCE:             region[2],
			CITY:                 region[3],
			SRC_IP:               clientIP,
			SRC_PORT:             clientPort,
			CREATE_TIME:          datetimeNow.Format("2006-01-02 15:04:05"),
			UNIX_ADD_TIME:        datetimeNow.UnixNano() / 1e6,
			CONTENT_LENGTH:       contentLength,
			COOKIES:              string(cookies),
			BODY:                 string(bodyByte),
			REQ_UUID:             uuid.GenUUID(),
			USER_CODE:            global.GWAF_USER_CODE,
			HOST_CODE:            hostCode,
			TenantId:             global.GWAF_TENANT_ID,
			RULE:                 "",
			ACTION:               "通过",
			Day:                  currentDay,
			POST_FORM:            r.PostForm.Encode(),
			TASK_FLAG:            -1,
			RISK_LEVEL:           0,      //危险等级
			GUEST_IDENTIFICATION: "正常访客", //访客身份识别
			TimeSpent:            0,
			NetSrcIp:             utils.GetSourceClientIP(r.RemoteAddr),
			SrcByteBody:          bodyByte,
			WebLogVersion:        global.GWEBLOG_VERSION,
			Scheme:               r.Proto,
			SrcURL:               []byte(r.RequestURI),
		}
		// 检查是否为WebSocket升级请求
		if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
			if r.TLS != nil {
				weblogbean.HOST = "wss://" + weblogbean.HOST
			} else {
				weblogbean.HOST = "ws://" + weblogbean.HOST
			}
		} else if r.TLS != nil {
			weblogbean.HOST = "https://" + weblogbean.HOST
		} else {
			weblogbean.HOST = "http://" + weblogbean.HOST
		}
		formValues := url.Values{}
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			// 解码 x-www-form-urlencoded 数据
			formValuest, err := url.ParseQuery(weblogbean.BODY)
			if err == nil {
				formValues = formValuest
			} else {
				fmt.Println("解码失败:", err)
				fmt.Println("解码失败:", weblogbean.BODY)
			}
		}

		// 检测是否已经被CC封禁
		ccCacheKey := enums.CACHE_CCVISITBAN_PRE + weblogbean.NetSrcIp
		if global.GCACHE_WAFCACHE.IsKeyExist(ccCacheKey) {
			// 使用新的IP封禁消息格式
			regionStr := strings.Join(region, ",")
			serverName := global.GWAF_CUSTOM_SERVER_NAME
			if serverName == "" {
				serverName = "未命名服务器"
			}
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.IPBanMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{
					OperaType: "CC封禁提醒",
					Server:    serverName,
				},
				Ip:       weblogbean.NetSrcIp + " (" + regionStr + ")",
				Reason:   "CC攻击，访问频次过高",
				Duration: 0, // CC封禁时长由配置决定
				Time:     time.Now().Format("2006-01-02 15:04:05"),
			})
			EchoErrorInfo(w, r, &weblogbean, "", "当前IP由于访问频次太高暂时无法访问", hostTarget, waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], false, "cc_attack")
			return
		}

		if host == hostTarget.Host.Host+":80" && !strings.HasPrefix(weblogbean.URL, global.GSSL_HTTP_CHANGLE_PATH) && hostTarget.Host.AutoJumpHTTPS == 1 && hostTarget.Host.Ssl == 1 {
			domainJump := ""
			if strings.Contains(host, ":") {
				partsJump := strings.Split(host, ":")
				if len(partsJump) == 2 {
					domainJump = partsJump[0]
				}
			}
			// 重定向到 HTTPS 版本的 URL
			targetHttpsUrl := fmt.Sprintf("%s%s%s", "https://", domainJump, r.URL.Path)
			// 只有在非标准端口时才显示端口号（443是标准端口）
			if hostTarget.Host.Port != 443 {
				targetHttpsUrl = fmt.Sprintf("%s%s:%d%s", "https://", domainJump, hostTarget.Host.Port, r.URL.Path)
			}
			if r.URL.RawQuery != "" {
				targetHttpsUrl += "?" + r.URL.RawQuery
			}
			zlog.Info(innerLogName, "jump https", targetHttpsUrl)
			http.Redirect(w, r, targetHttpsUrl, int(global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE))
			return
		}

		r.Header.Add("waf_req_uuid", weblogbean.REQ_UUID)

		if hostTarget.Host.GUARD_STATUS == 1 {
			//一系列检测逻辑
			handleBlock := func(checkFunc func(*http.Request, *innerbean.WebLog, url.Values, *wafenginmodel.HostSafe, *wafenginmodel.HostSafe) detection.Result) bool {
				detectionResult := checkFunc(r, &weblogbean, formValues, hostTarget, waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]])
				if detectionResult.IsBlock {
					if hostTarget.Host.LogOnlyMode == 1 {
						// 仅记录模式：记录攻击日志但不阻断请求
						weblogbean.LogOnlyMode = 1
						weblogbean.RULE = detectionResult.Title
						return false
					} else {
						decrementMonitor(hostCode)
						// 根据检测结果的标题推断攻击类型
						attackType := inferAttackType(detectionResult.Title)
						EchoErrorInfo(w, r, &weblogbean, detectionResult.Title, detectionResult.Content, hostTarget, waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], true, attackType)
						return true
					}
				}
				return false
			}
			globalHostSafe := waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]]

			// 插件预检查（在所有检测之前）
			if handleBlock(func(r *http.Request, weblogbean *innerbean.WebLog, formValues url.Values, hostTarget *wafenginmodel.HostSafe, globalHost *wafenginmodel.HostSafe) detection.Result {
				return waf.checkWithPlugins(r, weblogbean, hostTarget, "pre_check")
			}) {
				// 插件拦截，记录日志并返回
				return
			}

			// 检测白名单开始
			detectionWhiteResult := detection.Result{JumpGuardResult: false}
			checkFunctions := []func(*http.Request, *innerbean.WebLog, url.Values, *wafenginmodel.HostSafe, *wafenginmodel.HostSafe) detection.Result{
				waf.CheckAllowIP,
				waf.CheckAllowURL,
				waf.CheckAllowCallBackIP,
			}
			for _, checkFunc := range checkFunctions {
				detectionWhiteResult = checkFunc(r, &weblogbean, formValues, hostTarget, globalHostSafe)
				if detectionWhiteResult.JumpGuardResult == true {
					break
				}
			}
			//检测白名单结束
			if detectionWhiteResult.JumpGuardResult == false {

				if handleBlock(waf.CheckDenyIP) {
					return
				}
				if handleBlock(waf.CheckDenyURL) {
					return
				}

				hostDefense := model.ParseHostsDefense(hostTarget.Host.DEFENSE_JSON)
				//检测爬虫bot
				if hostDefense.DEFENSE_BOT == 1 {
					if handleBlock(waf.CheckBot) {
						return
					}
				}
				//检测sqli
				if hostDefense.DEFENSE_SQLI == 1 {
					if handleBlock(waf.CheckSql) {
						return
					}
				}
				//检测xss
				if hostDefense.DEFENSE_XSS == 1 {
					if handleBlock(waf.CheckXss) {
						return
					}
				}
				//检测扫描工具
				if hostDefense.DEFENSE_SCAN == 1 {
					if handleBlock(waf.CheckSan) {
						return
					}
				}
				//检测RCE
				if hostDefense.DEFENSE_RCE == 1 {
					if handleBlock(waf.CheckRce) {
						return
					}
				}
				//目录穿越检测
				if hostDefense.DEFENSE_DIR_TRAVERSAL == 1 {
					if handleBlock(waf.CheckDirTraversal) {
						return
					}
				}
				//检测CC
				if handleBlock(waf.CheckCC) {
					return
				}
				//规则判断
				if handleBlock(waf.CheckRule) {
					return
				}
				//检测敏感词
				if hostDefense.DEFENSE_SENSITIVE == 1 {
					if handleBlock(waf.CheckSensitive) {
						return
					}
				}
				//检测OWASP
				if handleBlock(waf.CheckOwasp) {
					return
				}

				// 添加防盗链检查
				if handleBlock(waf.CheckAntiLeech) {
					return
				}

				// 验证码检测
				captchaConfig := model.ParseCaptchaConfig(hostTarget.Host.CaptchaJSON)

				if captchaConfig.IsEnableCaptcha == 1 {
					if !waf.checkCaptchaToken(r, weblogbean, captchaConfig) {
						// 检查当前URL是否在排除列表中
						currentURL := strings.ToLower(r.URL.Path)
						isExcluded := false

						// 获取验证码路径前缀
						captchaPathPrefix := captchaConfig.PathPrefix
						if captchaPathPrefix == "" {
							captchaPathPrefix = "/samwaf_captcha"
						}

						// 检查是否是验证码相关路径，如果是则直接处理
						if strings.HasPrefix(currentURL, captchaPathPrefix+"/") || currentURL == captchaPathPrefix {
							waf.handleCaptchaRequest(w, r, &weblogbean, captchaConfig, captchaPathPrefix)
							return
						}

						if len(captchaConfig.ExcludeURLs) > 0 {
							// 将换行分隔的URL列表拆分为数组
							excludeURLs := strings.Split(captchaConfig.ExcludeURLs, "\n")
							for _, excludeURL := range excludeURLs {
								// 去除可能的空白字符并转为小写
								excludeURL = strings.TrimSpace(strings.ToLower(excludeURL))
								if excludeURL != "" && strings.HasPrefix(currentURL, excludeURL) {
									isExcluded = true
									break
								}
							}
						}
						if !isExcluded {
							waf.handleCaptchaRequest(w, r, &weblogbean, captchaConfig, captchaPathPrefix)
							return
						}
					}
				}
			}

		}

		if cacheConfig.IsEnableCache == 1 && !strings.HasPrefix(weblogbean.URL, global.GSSL_HTTP_CHANGLE_PATH) {
			cacheResp := wafwebcache.LoadWebDataFormCache(w, r, hostTarget, cacheConfig, &weblogbean)
			if cacheResp != nil {
				// 将缓存的响应写回给客户端
				for k, v := range cacheResp.Header {
					for _, val := range v {
						w.Header().Add(k, val)
					}
				}

				w.Header().Add("X-Cache", "HIT")
				w.WriteHeader(cacheResp.StatusCode)
				// 读取并写入响应体
				if cacheResp.Body != nil {
					body, _ := ioutil.ReadAll(cacheResp.Body)
					cacheResp.Body.Close()
					w.Write(body)

					// 重新创建一个body供后续使用
					cacheResp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
				}

				// 设置响应并返回
				r.Response = cacheResp
				return
			}
		}
		// 如果开启了静态站点服务且请求路径匹配前缀
		if staticSiteConfig.IsEnableStaticSite == 1 {

			if strings.HasPrefix(weblogbean.URL, global.GSSL_HTTP_CHANGLE_PATH) {
				//Challenge /.well-known/acme-challenge/2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8
				urls := strings.Split(weblogbean.URL, "/")
				if len(urls) == 4 {
					challengeFile := urls[3]
					//检测challengeFile是否合法
					if !utils.IsValidChallengeFile(challengeFile) {
						return
					}
					//当前路径 data/vhost/domain code 变量下
					// 需要读取的文件路径
					filePath := utils.GetCurrentDir() + "/data/vhost/" + weblogbean.HOST_CODE + "/.well-known/acme-challenge/" + challengeFile

					// 调用读取文件的函数
					content, err := utils.ReadFile(filePath)
					if err != nil {
						zlog.Error("Error reading file: %v", err.Error())
						return
					}
					if content != "" {
						// 创建新的Response对象
						r.Response = &http.Response{
							StatusCode:    http.StatusOK,
							Status:        http.StatusText(http.StatusOK),
							Body:          io.NopCloser(bytes.NewBuffer([]byte(content))),
							ContentLength: int64(len(content)),
							Header:        make(http.Header),
							Proto:         "HTTP/1.1",
							ProtoMajor:    1,
							ProtoMinor:    1,
						}
						r.Response.Header.Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))

						// 直接写入响应到客户端
						w.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(content))

						weblogbean.ACTION = "放行"
						weblogbean.STATUS = r.Response.Status
						weblogbean.STATUS_CODE = r.Response.StatusCode
						weblogbean.TASK_FLAG = 1
						global.GQEQUE_LOG_DB.Enqueue(&weblogbean)
						return
					}
				}
			} else {
				waf.serveStaticFile(w, r, staticSiteConfig, &weblogbean, hostTarget)
				return
			}
		}
		//如果正常的流量不记录请求原始包
		if global.GCONFIG_RECORD_ALL_SRC_BYTE_INFO == 0 {
			weblogbean.SrcByteBody = nil
		}
		//基本验证是否开关是否开启
		if hostTarget.Host.IsEnableHttpAuthBase == 1 {
			bHttpAuthBaseResult, sHttpAuthBaseResult := waf.DoHttpAuthBase(hostTarget, w, r)
			if bHttpAuthBaseResult == true {
				// 记录日志
				weblogbean.RES_BODY = sHttpAuthBaseResult
				weblogbean.ACTION = "禁止"
				global.GQEQUE_LOG_DB.Enqueue(&weblogbean)
				return
			}
		}

		// 日志保存时候也是脱敏保存防止，数据库密码被破解，遭到敏感信息遭到泄露
		if global.GCONFIG_RECORD_LOG_DESENSITIZE == 1 && weblogbean.BODY != "" {
			weblogbean.BODY = utils.DeSenTextByCustomMark(enums.DLP_MARK_RULE_LoginSensitiveInfoMaskRule, weblogbean.BODY)
		}
		remoteUrl, err := url.Parse(hostTarget.TargetHost)
		if err != nil {
			zlog.Debug("target parse fail:", zap.Any("", err))
			return
		}

		// 记录前置校验耗时
		weblogbean.PreCheckCost = time.Now().UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME

		// 在请求上下文中存储自定义数据
		ctx := context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{
			Weblog:   &weblogbean,
			HostCode: hostCode,
		})

		// 代理请求
		waf.ProxyHTTP(w, r, host, remoteUrl, clientIP, ctx, &weblogbean, hostTarget)

		return
	} else {
		w.WriteHeader(403)
		resBytes := []byte("403: Host forbidden " + host)
		_, err := w.Write(resBytes)
		if err != nil {
			zlog.Debug("write fail:", zap.Any("", err))
			return
		}
		// 获取请求报文的内容长度
		contentLength := r.ContentLength

		//server_online[8081].Svr.Close()
		var bodyByte []byte

		// 拷贝一份request的Body ,控制不记录大文件的情况 ，先写死的
		if r.Body != nil && r.Body != http.NoBody && contentLength < (global.GCONFIG_RECORD_MAX_BODY_LENGTH) {
			bodyByte, _ = io.ReadAll(r.Body)
			// 把刚刚读出来的再写进去，不然后面解析表单数据就解析不到了
			r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
		}
		cookies, _ := json.Marshal(r.Cookies())
		header, _ := json.Marshal(r.Header)
		// 取出客户IP
		ipErr, clientIP, clientPort := waf.getClientIP(r, strings.Split(global.GCONFIG_RECORD_PROXY_HEADER, ",")...)
		if ipErr != nil {
			zlog.Error("get client error", ipErr.Error())
			return
		}
		region := utils.GetCountry(clientIP)
		datetimeNow := time.Now()

		currentDay, _ := strconv.Atoi(datetimeNow.Format("20060102"))
		weblogbean := innerbean.WebLog{
			HOST:                 r.Host,
			URL:                  r.RequestURI,
			REFERER:              r.Referer(),
			USER_AGENT:           r.UserAgent(),
			METHOD:               r.Method,
			HEADER:               string(header),
			COUNTRY:              region[0],
			PROVINCE:             region[2],
			CITY:                 region[3],
			SRC_IP:               clientIP,
			SRC_PORT:             clientPort,
			CREATE_TIME:          datetimeNow.Format("2006-01-02 15:04:05"),
			UNIX_ADD_TIME:        datetimeNow.UnixNano() / 1e6,
			CONTENT_LENGTH:       contentLength,
			COOKIES:              string(cookies),
			BODY:                 string(bodyByte),
			REQ_UUID:             uuid.GenUUID(),
			USER_CODE:            global.GWAF_USER_CODE,
			HOST_CODE:            "",
			TenantId:             global.GWAF_TENANT_ID,
			RULE:                 "",
			ACTION:               "通过",
			Day:                  currentDay,
			STATUS:               "禁止访问",
			STATUS_CODE:          403,
			TASK_FLAG:            1,
			RISK_LEVEL:           1,       //危险等级
			GUEST_IDENTIFICATION: "未解析域名", //访客身份识别
			TimeSpent:            0,
			NetSrcIp:             utils.GetSourceClientIP(r.RemoteAddr),
			WebLogVersion:        global.GWEBLOG_VERSION,
			Scheme:               r.Proto,
			SrcURL:               []byte(r.RequestURI),
		}

		//记录响应body
		weblogbean.RES_BODY = string(resBytes)
		weblogbean.ACTION = "禁止"
		global.GQEQUE_LOG_DB.Enqueue(&weblogbean)
	}
}
func (waf *WafEngine) getClientIP(r *http.Request, headers ...string) (error, string, string) {
	for _, header := range headers {
		ip := r.Header.Get(header)
		if ip != "" {
			// 处理可能的多个 IP 地址，以逗号分隔，取第一个有效的
			ips := strings.Split(ip, ",")
			trimmedIP := strings.TrimSpace(ips[0])
			if utils.IsValidIPv4(trimmedIP) {
				return nil, trimmedIP, "0"
			}
			if utils.IsValidIPv6(ip) {
				return nil, ip, "0"
			}
			return errors.New("invalid IPv4 address from header: " + header + " value:" + ip), "", ""
		}
	}

	// 如果没有找到，使用 r.RemoteAddr
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err, "", ""
	}

	// 验证 IPv4 地址
	if utils.IsValidIPv4(ip) {
		return nil, ip, port
	}

	// 如果是 IPv6 地址，进一步检查是否是有效的 IPv6 地址
	if strings.Contains(ip, ":") {
		// 如果是 IPv6 地址，进一步检查是否是有效的 IPv6 地址
		if strings.Contains(ip, ":") {
			if utils.IsValidIPv6(ip) {
				return nil, ip, port
			} else {
				return errors.New("invalid IPv6 address from RemoteAddr: " + ip), "", ""
			}
		}
	}

	return errors.New("invalid IP address (not IPv4 or IPv6): " + ip), "", ""
}

func (waf *WafEngine) errorResponse() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {

		if wafHttpContext, ok := req.Context().Value("waf_context").(innerbean.WafHttpContextData); ok {
			weblogReq := wafHttpContext.Weblog

			requestInfo := fmt.Sprintf("Method: %s \r\nURL: %s   \r\nHeaders: %v", req.Method, req.URL.String(), req.Header)
			zlog.Error("服务不可用 response:", zap.Any("err", err.Error()), zap.String("request_info", requestInfo))

			resBytes := []byte("<html><head><title>服务不可用</title></head><body><center><h1>服务不可用</h1> <br><h3></h3></center></body> </html>")

			//记录响应Header信息
			resHeader := ""
			if req.Response != nil {
				for key, values := range req.Response.Header {
					for _, value := range values {
						resHeader += key + ": " + value + "\r\n"
					}
				}
			}

			weblogReq.ResHeader = resHeader
			weblogReq.ACTION = "放行"
			weblogReq.STATUS = "Service Unavailable"
			weblogReq.STATUS_CODE = 503
			weblogReq.RES_BODY = fmt.Sprintf("请求相关信息:%v \r\n 错误信息:%v \r\n", requestInfo, err.Error())
			weblogReq.TASK_FLAG = 1
			global.GQEQUE_LOG_DB.Enqueue(weblogReq)
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, writeErr := w.Write(resBytes); writeErr != nil {
				zlog.Debug("write fail:", zap.Any("err", writeErr))
				return
			}
		}

		return
	}
}
func (waf *WafEngine) modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		resp.Header.Set("X-Xss-Protection", "1; mode=block")
		if global.GCONFIG_RECORD_HIDE_SERVER_HEADER == 1 {
			resp.Header.Del("Server")
			resp.Header.Del("X-Powered-By")
		}
		r := resp.Request
		// 检查是否为WebSocket协议切换
		if resp.StatusCode == http.StatusSwitchingProtocols {

			if wafHttpContext, ok := r.Context().Value("waf_context").(innerbean.WafHttpContextData); ok {
				weblogfrist := wafHttpContext.Weblog
				host := waf.HostCode[wafHttpContext.HostCode]
				weblogfrist.ACTION = "放行"
				weblogfrist.STATUS = resp.Status
				weblogfrist.STATUS_CODE = resp.StatusCode

				resHeader := ""
				for key, values := range resp.Header {
					for _, value := range values {
						resHeader += key + ": " + value + "\r\n"
					}
				}
				weblogfrist.ResHeader = resHeader

				datetimeNow := time.Now()
				weblogfrist.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME
				weblogfrist.TASK_FLAG = 1

				// 记录日志
				if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
					if waf.HostTarget[host].Host.EXCLUDE_URL_LOG == "" {
						global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
					} else {
						lines := strings.Split(waf.HostTarget[host].Host.EXCLUDE_URL_LOG, "\n")
						isRecordLog := true
						// 检查每一行
						for _, line := range lines {
							if strings.HasPrefix(weblogfrist.URL, line) {
								isRecordLog = false
							}
						}
						if isRecordLog {
							global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
						}
					}
				} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblogfrist.ACTION != "放行" {
					global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
				}
			}
			// 对于WebSocket连接，不修改响应体，直接返回
			return nil
		}
		if wafHttpContext, ok := r.Context().Value("waf_context").(innerbean.WafHttpContextData); ok {

			backendCheckStart := time.Now().UnixNano() / 1e6

			weblogfrist := wafHttpContext.Weblog

			host := waf.HostCode[wafHttpContext.HostCode]

			// 记录后端真实返回的状态码
			backendStatusCode := resp.StatusCode
			backendStatus := resp.Status

			weblogfrist.ACTION = "放行"
			weblogfrist.STATUS = resp.Status
			weblogfrist.STATUS_CODE = resp.StatusCode

			//返回内容的类型
			respContentType := strings.ToLower(resp.Header.Get("Content-Type"))
			respContentType = strings.Replace(respContentType, "; charset=utf-8", "", -1)
			respContentType = strings.Replace(respContentType, "; charset=gbk", "", -1)

			//记录静态日志
			isStaticAssist := utils.IsStaticAssist(resp, respContentType)

			// 检查是否为流式内容
			contentType := strings.ToLower(resp.Header.Get("Content-Type"))
			isStreamContent := strings.Contains(contentType, "text/event-stream") ||
				strings.Contains(contentType, "application/stream+json")

			//记录响应body
			if !isStaticAssist && resp.Body != nil && resp.Body != http.NoBody {

				// 如果是流式内容，使用流式处理器
				if isStreamContent {
					// 创建流式处理器包装原始响应体
					streamProcessor := waf.createStreamProcessor(resp.Body, wafHttpContext, host)
					resp.Body = io.NopCloser(streamProcessor)

					// 对于流式内容，跳过后续的常规处理逻辑
					// 但仍然记录基本的访问日志
					weblogfrist.ACTION = "放行"
					weblogfrist.STATUS = resp.Status
					weblogfrist.STATUS_CODE = resp.StatusCode
					weblogfrist.TASK_FLAG = 1

					// 记录响应Header信息
					resHeader := ""
					for key, values := range resp.Header {
						for _, value := range values {
							resHeader += key + ": " + value + "\r\n"
						}
					}
					weblogfrist.ResHeader = resHeader

					datetimeNow := time.Now()
					weblogfrist.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME
					weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart //响应数据处理时间

					// 记录流式访问日志
					if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
						if waf.HostTarget[host].Host.EXCLUDE_URL_LOG == "" {
							global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
						} else {
							lines := strings.Split(waf.HostTarget[host].Host.EXCLUDE_URL_LOG, "\n")
							isRecordLog := true
							for _, line := range lines {
								if strings.HasPrefix(weblogfrist.URL, line) {
									isRecordLog = false
								}
							}
							if isRecordLog {
								global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
							}
						}
					} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblogfrist.ACTION != "放行" {
						global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
					}

					return nil
				}

				ldpFlag := false
				// 将请求URL转为小写，用于不区分大小写的比较
				lowerRequestURI := strings.ToLower(resp.Request.RequestURI)

				//隐私保护（局部）
				for i := 0; i < len(waf.HostTarget[host].LdpUrlLists); i++ {
					// 将规则URL也转为小写
					lowerRuleURL := strings.ToLower(waf.HostTarget[host].LdpUrlLists[i].Url)

					if (waf.HostTarget[host].LdpUrlLists[i].CompareType == "等于" && lowerRuleURL == lowerRequestURI) ||
						(waf.HostTarget[host].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerRuleURL)) ||
						(waf.HostTarget[host].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerRuleURL)) ||
						(waf.HostTarget[host].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerRuleURL)) {

						ldpFlag = true
						break
					}
				}
				//隐私保护（全局）
				for i := 0; i < len(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists); i++ {
					// 将全局规则URL也转为小写
					lowerGlobalRuleURL := strings.ToLower(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)

					if (waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerRequestURI) ||
						(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerGlobalRuleURL)) ||
						(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerGlobalRuleURL)) ||
						(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerGlobalRuleURL)) {

						ldpFlag = true
						break
					}
				}
				if ldpFlag == true {
					orgContentBytes, charsetName, responseEncodingError := waf.getOrgContent(resp, isStaticAssist, waf.HostTarget[host].Host.DefaultEncoding)
					if responseEncodingError == nil {
						newPayload := []byte("" + utils.DeSenText(string(orgContentBytes)))
						finalCompressBytes, _ := waf.compressContent(resp, isStaticAssist, newPayload, charsetName)

						resp.Body = io.NopCloser(bytes.NewBuffer(finalCompressBytes))
						// head 修改追加内容
						resp.ContentLength = int64(len(finalCompressBytes))
						resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalCompressBytes)), 10))
					} else {
						resp.Body = io.NopCloser(bytes.NewBuffer(orgContentBytes))
						zlog.Warn(fmt.Sprintf("识别响应内容编码失败，隐私防护不可用 %v，请求URL: %s ,可以在主机其他设置里面设置默认编码", responseEncodingError, r.URL.String()))
					}

				}
				//编码转换，自动检测网页编码   resp *http.Response
				orgContentBytes, charsetName, responseEncodingError := waf.getOrgContent(resp, isStaticAssist, waf.HostTarget[host].Host.DefaultEncoding)
				if responseEncodingError == nil {
					if global.GCONFIG_RECORD_RESP == 1 {
						if resp.ContentLength < global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH {
							weblogfrist.RES_BODY = string(orgContentBytes)
							weblogfrist.SrcByteResBody = orgContentBytes
						}
					}

					//处理敏感词
					if waf.CheckResponseSensitive() {
						matchBodyResult := waf.SensitiveManager.MultiPatternSearch([]rune(string(orgContentBytes)), false)
						if len(matchBodyResult) > 0 {
							sensitive := matchBodyResult[0].CustomData.(model.Sensitive)

							if sensitive.CheckDirection != "in" {
								weblogfrist.RISK_LEVEL = 1
								if sensitive.Action == "deny" {
									if waf.HostTarget[host].Host.LogOnlyMode == 1 {
										// 仅记录模式：记录攻击日志但不阻断请求
										weblogfrist.LogOnlyMode = 1
										weblogfrist.GUEST_IDENTIFICATION = "触发敏感词"
										weblogfrist.RULE = "敏感词检测：" + string(matchBodyResult[0].Word)

									} else {
										EchoResponseErrorInfo(resp, weblogfrist, "敏感词检测："+string(matchBodyResult[0].Word), "敏感词内容", waf.HostTarget[host], waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], true, "sensitive_word")
										return nil
									}
								} else {
									words := processSensitiveWords(matchBodyResult, "in")
									weblogfrist.GUEST_IDENTIFICATION = "触发敏感词"
									weblogfrist.RULE = "敏感词检测：" + strings.Join(words, ",")
									for _, word := range words {
										orgContentBytes = bytes.ReplaceAll(orgContentBytes, []byte(word), []byte(global.GWAF_HTTP_SENSITIVE_REPLACE_STRING))

									}
								}
							}
						}
					}
					//将数据在回写上去
					finalCompressBytes, _ := waf.compressContent(resp, isStaticAssist, orgContentBytes, charsetName)
					resp.Body = io.NopCloser(bytes.NewBuffer(finalCompressBytes))
					resp.ContentLength = int64(len(finalCompressBytes))
					resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalCompressBytes)), 10))

				} else {
					resp.Body = io.NopCloser(bytes.NewBuffer(orgContentBytes))
					zlog.Warn(fmt.Sprintf("识别响应内容编码失败，响应日志，敏感词替换 不可用 %v，请求URL: %s ,可以在主机其他设置里面设置默认编码", responseEncodingError, r.URL.String()))
				}
			}

			//检测cache
			cacheConfig := model.CacheConfig{
				IsEnableCache:   0,
				CacheLocation:   "",
				CacheDir:        "",
				MaxFileSizeMB:   0,
				MaxMemorySizeMB: 0,
			}
			err := json.Unmarshal([]byte(waf.HostTarget[host].Host.CacheJSON), &cacheConfig)
			if err != nil {
				zlog.Debug("解析cache json失败")
			}
			if cacheConfig.IsEnableCache == 1 && !strings.HasPrefix(weblogfrist.URL, global.GSSL_HTTP_CHANGLE_PATH) {
				wafwebcache.StoreWebDataCache(resp, waf.HostTarget[host], cacheConfig, weblogfrist)
			}

			if !isStaticAssist {
				datetimeNow := time.Now()
				weblogfrist.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME

				// 根据配置决定是否检查HTTP响应代码并重定向到本地
				if strings.HasPrefix(weblogfrist.URL, global.GSSL_HTTP_CHANGLE_PATH) {
					zlog.Info("acme-challenge", weblogfrist.HOST, weblogfrist.URL)
					if global.GCONFIG_RECORD_SSLHTTP_CHECK == 0 || resp.StatusCode == 404 || resp.StatusCode == 301 || resp.StatusCode == 302 {
						//如果远端HTTP01不存在挑战验证文件，那么我们映射到走本地再试一下
						//或者配置为不检查HTTP响应代码，直接走本地

						//Challenge /.well-known/acme-challenge/2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8
						urls := strings.Split(weblogfrist.URL, "/")
						if len(urls) == 4 {
							challengeFile := urls[3]
							//检测challengeFile是否合法
							if !utils.IsValidChallengeFile(challengeFile) {
								zlog.Error("challengeFile is invalid", challengeFile)
								return nil
							}
							//当前路径 data/vhost/domain code 变量下
							// 需要读取的文件路径
							filePath := utils.GetCurrentDir() + "/data/vhost/" + weblogfrist.HOST_CODE + "/.well-known/acme-challenge/" + challengeFile

							// 调用读取文件的函数
							content, err := utils.ReadFile(filePath)
							if err != nil {
								zlog.Error("Error reading file: %v", err.Error())
							}
							if content != "" {
								resp.StatusCode = http.StatusOK
								resp.Status = http.StatusText(http.StatusOK)
								resp.Body = io.NopCloser(bytes.NewBuffer([]byte(content)))
								resp.ContentLength = int64(len(content))
								resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
								resp.Header.Del("Content-Encoding")
								weblogfrist.ACTION = "放行"
								weblogfrist.STATUS = resp.Status
								weblogfrist.STATUS_CODE = resp.StatusCode
								weblogfrist.TASK_FLAG = 1
								weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart //响应数据处理时间
								global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
							}
						}
					} else if global.GCONFIG_RECORD_SSLHTTP_CHECK == 1 {
						// 当配置为检查HTTP响应码且响应不是404/301/302时，记录警告信息
						zlog.Warn(fmt.Sprintf("ACME Challenge检测：域名 %s 的 URL %s 返回了非预期的状态码 %d，影响证书验证，可在系统配置里面将sslhttp_check设置成0",
							weblogfrist.HOST, weblogfrist.URL, resp.StatusCode))
					}
				} else {
					// 检查是否需要应用自定义错误页面（非 ACME Challenge 请求）
					statusCodeKey := strconv.Itoa(backendStatusCode)
					var customBlockingPage *model.BlockingPage
					var useCustomPage bool

					// 优先检查网站级别的自定义错误页面配置
					if blockingPage, ok := waf.HostTarget[host].BlockingPage[statusCodeKey]; ok {
						customBlockingPage = &blockingPage
						useCustomPage = true
					} else if globalBlockingPage, ok := waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]].BlockingPage[statusCodeKey]; ok {
						// 检查全局级别的自定义错误页面配置
						customBlockingPage = &globalBlockingPage
						useCustomPage = true
					}

					// 如果找到自定义错误页面配置，则应用
					if useCustomPage && customBlockingPage != nil {
						// 先读取后端原始响应内容，用于日志记录
						var backendOriginalBody []byte
						if resp.Body != nil && resp.Body != http.NoBody {
							backendOriginalBody, _ = io.ReadAll(resp.Body)
							resp.Body.Close()
						}

						renderData := map[string]interface{}{
							"SAMWAF_REQ_UUID":       weblogfrist.REQ_UUID,
							"SAMWAF_BACKEND_STATUS": backendStatus,
							"SAMWAF_BACKEND_CODE":   backendStatusCode,
							"SAMWAF_BACKEND_BODY":   string(backendOriginalBody),
						}

						// 渲染自定义模板
						renderedBytes, err := renderTemplate(customBlockingPage.ResponseContent, renderData)
						var resBytes []byte
						if err == nil {
							resBytes = renderedBytes
						} else {
							resBytes = []byte(customBlockingPage.ResponseContent)
							zlog.Warn(fmt.Sprintf("模板渲染失败: %v, 使用原始内容", err))
						}

						// 设置自定义响应码（如果配置了）
						var customResponseCode int = backendStatusCode
						if customBlockingPage.ResponseCode != "" {
							if code, err := strconv.Atoi(customBlockingPage.ResponseCode); err == nil {
								customResponseCode = code
							}
						}

						// 清空现有的响应头并设置自定义响应头
						var headers []map[string]string
						if err := json.Unmarshal([]byte(customBlockingPage.ResponseHeader), &headers); err == nil {
							for _, header := range headers {
								if name, ok := header["name"]; ok {
									if value, ok := header["value"]; ok && value != "" {
										resp.Header.Set(name, value)
									}
								}
							}
						}

						// 更新响应
						resp.StatusCode = customResponseCode
						resp.Status = http.StatusText(customResponseCode)
						resp.Body = io.NopCloser(bytes.NewBuffer(resBytes))
						resp.ContentLength = int64(len(resBytes))
						resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(resBytes)), 10))

						// 记录响应Header信息
						resHeader := ""
						for key, values := range resp.Header {
							for _, value := range values {
								resHeader += key + ": " + value + "\r\n"
							}
						}
						weblogfrist.ResHeader = resHeader

						// 记录日志信息
						weblogfrist.ACTION = "放行"
						weblogfrist.STATUS = resp.Status
						weblogfrist.STATUS_CODE = resp.StatusCode
						weblogfrist.RES_BODY = string(backendOriginalBody)

						weblogfrist.TASK_FLAG = 1
						weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart

						// 记录日志 - 根据配置决定是否记录
						if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
							if waf.HostTarget[host].Host.EXCLUDE_URL_LOG == "" {
								global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
							} else {
								lines := strings.Split(waf.HostTarget[host].Host.EXCLUDE_URL_LOG, "\n")
								isRecordLog := true
								for _, line := range lines {
									if strings.HasPrefix(weblogfrist.URL, line) {
										isRecordLog = false
									}
								}
								if isRecordLog {
									global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
								}
							}
						} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblogfrist.ACTION != "放行" {
							// 自定义错误页也属于"异常"情况，需要记录
							global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
						}

						// 应用自定义错误页后直接返回
						return nil
					}

					//记录响应Header信息
					resHeader := ""
					for key, values := range resp.Header {
						for _, value := range values {
							resHeader += key + ": " + value + "\r\n"
						}
					}
					weblogfrist.ResHeader = resHeader
					weblogfrist.ACTION = "放行"
					weblogfrist.STATUS = resp.Status
					weblogfrist.STATUS_CODE = resp.StatusCode
					weblogfrist.TASK_FLAG = 1
					weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart //响应数据处理时间
					if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
						if waf.HostTarget[host].Host.EXCLUDE_URL_LOG == "" {
							global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
						} else {
							lines := strings.Split(waf.HostTarget[host].Host.EXCLUDE_URL_LOG, "\n")
							isRecordLog := true
							// 检查每一行
							for _, line := range lines {
								if strings.HasPrefix(weblogfrist.URL, line) {
									isRecordLog = false
								}
							}
							if isRecordLog {
								global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
							}
						}
					} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblogfrist.ACTION != "放行" {
						global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
					}
				}

			}
		} else {
			fmt.Println("weblog not found")
		}

		return nil
	}
}

func (waf *WafEngine) StartWaf() {

	waf.EngineCurrentStatus = 1
	var hosts []model.Hosts
	//是否有初始化全局保护
	global.GWAF_LOCAL_DB.Where("global_host = ?", 1).Find(&hosts)
	if hosts != nil && len(hosts) == 0 {
		//初始化全局保护
		var wafGlobalHost = &model.Hosts{
			BaseOrm: baseorm.BaseOrm{
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			Code:             uuid.GenUUID(),
			Host:             "全局网站",
			Port:             0,
			Ssl:              0,
			GUARD_STATUS:     0,
			REMOTE_SYSTEM:    "",
			REMOTE_APP:       "",
			Remote_host:      "",
			Remote_port:      0,
			Certfile:         "",
			Keyfile:          "",
			REMARKS:          "",
			GLOBAL_HOST:      1,
			START_STATUS:     0,
			UnrestrictedPort: 0,
			BindSslId:        "",
			AutoJumpHTTPS:    0,
		}
		global.GWAF_LOCAL_DB.Create(wafGlobalHost)
	}

	//初始化步骤[加载ip数据库]
	// 从嵌入的文件中读取内容

	//global.GCACHE_IP_CBUFF = main.Ip2regionBytes

	//第一步 检测合法性并加入到全局
	waf.LoadAllHost()

	wafSysLog := model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "信息",
		OpContent: "WAF启动",
	}
	global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

	waf.StartAllProxyServer()
}

// CloseWaf 关闭waf
func (waf *WafEngine) CloseWaf() {
	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			zlog.Debug("关闭 recover ", e)
		}
	}()
	wafSysLog := &model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "信息",
		OpContent: "WAF关闭",
	}
	global.GQEQUE_LOG_DB.Enqueue(wafSysLog)
	waf.EngineCurrentStatus = 0

	waf.StopAllProxyServer()
	//重置信息
	waf.HostTarget = map[string]*wafenginmodel.HostSafe{}
	waf.HostCode = map[string]string{}
	waf.HostTargetNoPort = map[string]string{}
	waf.ServerOnline.Clear()
	waf.AllCertificate = AllCertificate{
		Mux: sync.Mutex{},
		Map: map[string]*tls.Certificate{},
	}
	// 清除Transport缓存池

	waf.TransportMux.Lock()
	waf.TransportPool = map[string]*http.Transport{}
	defer waf.TransportMux.Unlock()

}

// 清除代理
func (waf *WafEngine) ClearProxy(hostCode string) {
	var list []model.LoadBalance
	global.GWAF_LOCAL_DB.Where("host_code = ? ", hostCode).Find(&list)
	if waf.HostTarget[waf.HostCode[hostCode]] != nil {
		waf.HostTarget[waf.HostCode[hostCode]].Mux.Lock()
		defer waf.HostTarget[waf.HostCode[hostCode]].Mux.Unlock()
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceRuntime.RevProxies = []*wafproxy.ReverseProxy{}
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceRuntime.WeightRoundRobinBalance = loadbalance.NewWeightRoundRobinBalance(hostCode)
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceRuntime.IpHashBalance = loadbalance.NewConsistentHashBalance(nil, hostCode)
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceLists = list
	}
}

// 开启所有代理
func (waf *WafEngine) StartAllProxyServer() {

	waf.ServerOnline.Range(func(port int, v innerbean.ServerRunTime) bool {
		waf.StartProxyServer(v)
		return true
	})
	waf.EnumAllPortProxyServer()

	waf.ReLoadSensitive()
}

// 罗列端口
func (waf *WafEngine) EnumAllPortProxyServer() {
	onlinePorts := ""
	waf.ServerOnline.Range(func(port int, v innerbean.ServerRunTime) bool {
		onlinePorts = strconv.Itoa(v.Port) + "," + onlinePorts
		return true
	})
	global.GWAF_RUNTIME_CURRENT_WEBPORT = onlinePorts
}

func (waf *WafEngine) StartProxyServer(innruntime innerbean.ServerRunTime) {
	if innruntime.Status == 0 {
		//启动完成的就不进这里了
		return
	}
	if innruntime.ServerType == "" {
		//如果是空的就不进行了
		return
	}
	go func(innruntime innerbean.ServerRunTime) {

		if (innruntime.ServerType) == "https" {

			defer func() {
				e := recover()
				if e != nil { // 捕获该协程的panic 111111
					zlog.Warn("https recover ", e)
				}
			}()
			var svr *http.Server
			// 检查是否启用HTTPS重定向服务器
			if global.GCONFIG_ENABLE_HTTPS_REDIRECT == 1 {
				// 使用新的重定向服务器
				redirectServer := &wafhttpserver.RedirectingHTTPSServer{
					Server: &http.Server{
						Addr:    ":" + strconv.Itoa(innruntime.Port),
						Handler: waf,
						TLSConfig: &tls.Config{
							GetCertificate: waf.GetCertificateFunc,
							MinVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMinVerson),
							MaxVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMaxVerson),
						},
					},
				}
				svr = redirectServer.Server

				serclone, _ := waf.ServerOnline.Get(innruntime.Port)
				serclone.Svr = svr
				serclone.Status = 0
				waf.ServerOnline.Set(innruntime.Port, serclone)
				zlog.Info("启动HTTPS重定向服务器" + strconv.Itoa(innruntime.Port))
				err := redirectServer.ListenAndServeTLS("", "")
				if err == http.ErrServerClosed {
					zlog.Error("[HTTPServer] https redirect server has been close, cause:[%v]", err)
				}
			} else {
				svr = &http.Server{
					Addr:    ":" + strconv.Itoa(innruntime.Port),
					Handler: waf,
					TLSConfig: &tls.Config{
						GetCertificate: waf.GetCertificateFunc,
						MinVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMinVerson),
						MaxVersion:     utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMaxVerson),
					},
				}
				serclone, _ := waf.ServerOnline.Get(innruntime.Port)
				serclone.Svr = svr
				serclone.Status = 0
				waf.ServerOnline.Set(innruntime.Port, serclone)
				zlog.Info("启动HTTPS 服务器" + strconv.Itoa(innruntime.Port))

				if global.GCONFIG_ENABLE_HTTP3 == 1 {
					h3 := &http3.Server{
						Addr:      ":" + strconv.Itoa(innruntime.Port),
						Handler:   waf,
						TLSConfig: svr.TLSConfig,
					}
					svr.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						h3.SetQUICHeaders(w.Header())
						waf.ServeHTTP(w, r)
					})
					go func() {
						defer func() {
							e := recover()
							if e != nil { // 捕获该协程的panic
								zlog.Warn("https recover ", e)
							}
						}()
						zlog.Info("启动HTTPS 3 服务器" + strconv.Itoa(innruntime.Port))
						serclone.H3 = h3
						err := h3.ListenAndServe()
						if err == http.ErrServerClosed {
							zlog.Error("[HTTP3Server] https server has been close, cause:[%v]", err)
						} else {
							wafSysLog := model.WafSysLog{
								BaseOrm: baseorm.BaseOrm{
									Id:          uuid.GenUUID(),
									USER_CODE:   global.GWAF_USER_CODE,
									Tenant_ID:   global.GWAF_TENANT_ID,
									CREATE_TIME: customtype.JsonTime(time.Now()),
									UPDATE_TIME: customtype.JsonTime(time.Now()),
								},
								OpType:    "系统运行错误",
								OpContent: "HTTPS3端口被占用: " + strconv.Itoa(innruntime.Port) + ",请检查",
							}
							global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)
						}
					}()
				}

				ln, err := net.Listen("tcp", svr.Addr)
				if err != nil {
					zlog.Error("https listen fail", err.Error())
					return
				}
				if global.GCONFIG_ENABLE_PROXY_PROTOCOL == 1 {
					ln = &proxyproto.Listener{Listener: ln}
				}
				err = svr.ServeTLS(ln, "", "")
				if err == http.ErrServerClosed {
					zlog.Error("[HTTPServer] https server has been close, cause:[%v]", err)
				} else {
					//TODO 记录如果https 端口被占用的情况 记录日志 且应该推送websocket
					wafSysLog := model.WafSysLog{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						OpType:    "系统运行错误",
						OpContent: "HTTPS端口被占用: " + strconv.Itoa(innruntime.Port) + ",请检查",
					}
					global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)
					zlog.Error("[HTTPServer] https server start fail, cause:[%v]", err)
				}
				zlog.Info("server https shutdown")
			}
		} else {
			defer func() {
				e := recover()
				if e != nil { // 捕获该协程的panic 111111
					zlog.Warn("http recover ", e)
				}
			}()
			svr := &http.Server{
				Addr:    ":" + strconv.Itoa(innruntime.Port),
				Handler: waf,
			}
			serclone, _ := waf.ServerOnline.Get(innruntime.Port)
			serclone.Svr = svr
			serclone.Status = 0

			waf.ServerOnline.Set(innruntime.Port, serclone)

			zlog.Info("启动HTTP 服务器" + strconv.Itoa(innruntime.Port))
			ln, err := net.Listen("tcp", svr.Addr)
			if err != nil {
				zlog.Error("http listen fail", err.Error())
				return
			}
			if global.GCONFIG_ENABLE_PROXY_PROTOCOL == 1 {
				ln = &proxyproto.Listener{Listener: ln}

			}
			err = svr.Serve(ln)
			if err == http.ErrServerClosed {
				zlog.Warn("[HTTPServer] http server has been close, cause:[%v]", err)
			} else {
				//TODO 记录如果http 端口被占用的情况 记录日志 且应该推送websocket
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "系统运行错误",
					OpContent: "HTTP端口被占用: " + strconv.Itoa(innruntime.Port) + ",请检查",
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)
				zlog.Error("[HTTPServer] http server start fail, cause:[%v]", err)
			}
			zlog.Info("server  http shutdown")
		}

	}(innruntime)
}

// 关闭所有代理服务
func (waf *WafEngine) StopAllProxyServer() {
	waf.ServerOnline.Range(func(port int, v innerbean.ServerRunTime) bool {
		waf.StopProxyServer(v)
		return true
	})
}

// 关闭指定代理服务
func (waf *WafEngine) StopProxyServer(v innerbean.ServerRunTime) {
	if v.Svr != nil {
		v.Svr.Close()
	}
	if v.H3 != nil {
		v.H3.Close()
	}
}
func (waf *WafEngine) ClearCcWindows() {
	// 清理所有主机的IP限流器记录
	for _, hostSafe := range waf.HostTarget {
		if hostSafe.PluginIpRateLimiter != nil {
			hostSafe.PluginIpRateLimiter.CleanupOldRecords()
		}
	}
}

// ClearCcWindowsForIP 清理特定IP的CC限流记录
func (waf *WafEngine) ClearCcWindowsForIP(ip string) {
	// 遍历所有主机，清理指定IP的限流记录
	hostCount := 0
	for hostKey, hostSafe := range waf.HostTarget {
		if hostSafe.PluginIpRateLimiter != nil {
			// 获取清理前的请求计数
			var countBefore int
			countBefore = hostSafe.PluginIpRateLimiter.GetRequestCount(ip)

			// 清理该IP的限流记录
			hostSafe.PluginIpRateLimiter.ClearWindowForIP(ip)
			hostCount++

			// 获取清理后的请求计数
			var countAfter int
			countAfter = hostSafe.PluginIpRateLimiter.GetRequestCount(ip)

			// 打印清理前后的计数信息
			zlog.Debug(fmt.Sprintf("主机 %s 的 IP %s 限流记录: 清理前=%d, 清理后=%d",
				hostKey, ip, countBefore, countAfter))
		}
	}

	zlog.Debug(fmt.Sprintf("已清理 IP %s 在 %d 个主机上的 CC 限流记录", ip, hostCount),
		zap.String("ip", ip),
		zap.Int("hostCount", hostCount))
}
func (waf *WafEngine) ApplyAntiCCConfig(hostCode string, antiCC model.AntiCC) {
	targetKey, ok := waf.HostCode[hostCode]
	if !ok {
		zlog.Debug("Anticc reload skip: hostCode not found", zap.String("hostCode", hostCode))
		return
	}
	hostSafe, ok := waf.HostTarget[targetKey]
	if !ok {
		zlog.Debug("Anticc reload skip: hostTarget not found", zap.String("targetKey", targetKey))
		return
	}

	hostSafe.Mux.Lock()
	defer hostSafe.Mux.Unlock()

	if antiCC.Id == "" {
		// 关闭CC防护
		hostSafe.PluginIpRateLimiter = nil
		hostSafe.AntiCCBean = antiCC
		zlog.Debug("Anticc disabled", zap.String("hostCode", hostCode))
		return
	}

	// 与初始化逻辑保持一致：支持滑动窗口/平均速率
	if antiCC.LimitMode == "window" {
		hostSafe.PluginIpRateLimiter = webplugin.NewWindowIPRateLimiter(antiCC.Rate, antiCC.Limit)
	} else {
		hostSafe.PluginIpRateLimiter = webplugin.NewIPRateLimiter(rate.Limit(antiCC.Rate), antiCC.Limit)
	}
	if antiCC.IsEnableRule {
		hostSafe.PluginIpRateLimiter.Rule = &utils.RuleHelper{}
		hostSafe.PluginIpRateLimiter.Rule.InitRuleEngine()
		hostSafe.PluginIpRateLimiter.Rule.LoadRuleString(antiCC.RuleContent)
	}
	hostSafe.AntiCCBean = antiCC

	zlog.Debug("远程配置", zap.Any("Anticc", antiCC))
	// ... existing code ...
}

// checkWithPlugins 使用插件系统检查请求
// 返回检测结果
// 注意：此方法预留用于未来的插件集成
// 当前版本中，插件管理器的实际调用逻辑需要在 go-plugin 集成后完善
func (waf *WafEngine) checkWithPlugins(r *http.Request, weblogbean *innerbean.WebLog, hostTarget *wafenginmodel.HostSafe, group string) detection.Result {
	// 检查插件管理器是否存在
	if waf.PluginManager == nil {
		return detection.Result{IsBlock: false}
	}

	// 类型断言获取插件管理器（定义需要的方法）
	pluginManager, ok := waf.PluginManager.(interface {
		CheckRequest(ctx context.Context, group string, ip string, requestPath string, userAgent string, method string, host string) (bool, string)
	})

	// 如果类型断言失败，直接返回
	if !ok {
		return detection.Result{IsBlock: false}
	}

	// 提取请求信息 - 使用已有的 getClientIP 方法
	_, clientIP, _ := waf.getClientIP(r, strings.Split(global.GCONFIG_RECORD_PROXY_HEADER, ",")...)
	if clientIP == "" {
		// 如果获取 IP 失败，从 RemoteAddr 获取
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}
	requestPath := r.URL.Path
	userAgent := r.UserAgent()

	// 调用插件管理器检查请求
	ctx := context.Background()
	isBlock, reason := pluginManager.CheckRequest(ctx, group, clientIP, requestPath, userAgent, r.Method, r.Host)

	// 如果插件要求拦截
	if isBlock {
		// 记录到日志
		if weblogbean != nil && weblogbean.REQ_UUID == "" {
			weblogbean.REQ_UUID = uuid.GenUUID()
		}
		if weblogbean != nil {
			weblogbean.RULE = "插件拦截"
		}

		return detection.Result{
			IsBlock: true,
			Title:   "插件拦截",
			Content: reason,
		}
	}

	// 插件检查通过，不拦截
	return detection.Result{IsBlock: false}
}
