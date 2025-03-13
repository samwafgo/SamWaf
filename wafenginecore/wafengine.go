package wafenginecore

import (
	"SamWaf/common/domaintool"
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
	"SamWaf/wafproxy"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	goahocorasick "github.com/samwafgo/ahocorasick"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	ServerOnline map[int]innerbean.ServerRunTime

	AllCertificate      AllCertificate //所有证书
	EngineCurrentStatus int            // 当前waf引擎状态

	//敏感词管理
	Sensitive        []model.Sensitive //敏感词
	SensitiveManager *goahocorasick.Machine
}

func (waf *WafEngine) Error() string {
	fs := "HTTP: %d, HostCode: %d, Message: %s"
	return fmt.Sprintf(fs)
}
func (waf *WafEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	innerLogName := "WafEngine ServeHTTP"
	atomic.AddUint64(&global.GWAF_RUNTIME_QPS, 1) // 原子增加计数器
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

	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			fmt.Println("11recover ", e)
			debug.PrintStack() // 打印堆栈信息

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

	// 检查域名是否已经注册
	if findHost == true {
		hostTarget := waf.HostTarget[waf.HostCode[targetCode]]
		hostCode := hostTarget.Host.Code

		incrementMonitor(hostCode)
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
		_, ok := waf.ServerOnline[hostTarget.Host.Remote_port]
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

		// 获取请求报文的内容长度
		contentLength := r.ContentLength
		var bodyByte []byte

		// 拷贝一份request的Body ,控制不记录大文件的情况 ，先写死的
		if r.Body != nil && r.Body != http.NoBody && contentLength < (global.GCONFIG_RECORD_MAX_BODY_LENGTH) {
			bodyByte, _ = io.ReadAll(r.Body)
			// 把刚刚读出来的再写进去，不然后面解析表单数据就解析不到了
			r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
		}
		cookies, _ := json.Marshal(r.Cookies())
		header := ""
		for key, values := range r.Header {
			for _, value := range values {
				header += key + ": " + value + "\r\n"
			}
		}

		region := utils.GetCountry(clientIP)

		currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))

		//URL 解码
		deRawQueryUrl := wafhttpcore.WafHttpCoreUrlEncode(r.URL.RawQuery, 10)
		datetimeNow := time.Now()
		weblogbean := innerbean.WebLog{
			HOST:                 host,
			URL:                  r.RequestURI,
			RawQuery:             deRawQueryUrl,
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
			REQ_UUID:             uuid.NewV4().String(),
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
		ccCacheKey := enums.CACHE_CCVISITBAN_PRE + clientIP
		if global.GCACHE_WAFCACHE.IsKeyExist(ccCacheKey) {
			visitIPError := fmt.Sprintf("当前IP已经被CC封禁，IP:%s 归属地区：%s", clientIP, region)
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "CC封禁提醒"},
				OperaCnt:        visitIPError,
			})
			EchoErrorInfo(w, r, weblogbean, "", "当前IP由于访问频次太高暂时无法访问", hostTarget, waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], false)
			return
		}

		if host == hostTarget.Host.Host+":80" && !strings.HasPrefix(weblogbean.URL, global.GSSL_HTTP_CHANGLE_PATH) && hostTarget.Host.AutoJumpHTTPS == 1 && hostTarget.Host.Ssl == 1 {
			// 重定向到 HTTPS 版本的 URL
			targetHttpsUrl := fmt.Sprintf("%s%s%s", "https://", r.Host, r.URL.Path)
			if hostTarget.Host.Port != 443 {
				targetHttpsUrl = fmt.Sprintf("%s%s:%d%s", "https://", r.Host, hostTarget.Host.Port, r.URL.Path)
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
					decrementMonitor(hostCode)
					EchoErrorInfo(w, r, weblogbean, detectionResult.Title, detectionResult.Content, hostTarget, waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], true)
					return true
				}
				return false
			}
			globalHostSafe := waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]]
			detectionWhiteResult := waf.CheckAllowIP(r, &weblogbean, formValues, hostTarget, globalHostSafe)
			if detectionWhiteResult.JumpGuardResult == false {
				detectionWhiteResult = waf.CheckAllowURL(r, weblogbean, formValues, hostTarget, globalHostSafe)
			}
			if detectionWhiteResult.JumpGuardResult == false {

				if handleBlock(waf.CheckDenyIP) {
					return
				}
				if handleBlock(waf.CheckDenyURL) {
					return
				}

				hostDefense := model.HostsDefense{
					DEFENSE_BOT:           1,
					DEFENSE_SQLI:          1,
					DEFENSE_XSS:           1,
					DEFENSE_SCAN:          1,
					DEFENSE_RCE:           1,
					DEFENSE_SENSITIVE:     1,
					DEFENSE_DIR_TRAVERSAL: 1,
				}
				err := json.Unmarshal([]byte(hostTarget.Host.DEFENSE_JSON), &hostDefense)
				if err != nil {
					zlog.Debug("解析defense json失败")
				}
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
				global.GQEQUE_LOG_DB.Enqueue(weblogbean)
				return
			}
		}

		// 日志保存时候也是脱敏保存防止，数据库密码被破解，遭到敏感信息遭到泄露
		if weblogbean.BODY != "" {
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
		waf.ProxyHTTP(w, r, host, remoteUrl, clientIP, ctx, weblogbean, hostTarget)
		decrementMonitor(hostCode)

		return
	} else {
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
			REQ_UUID:             uuid.NewV4().String(),
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
		global.GQEQUE_LOG_DB.Enqueue(weblogbean)
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
		if wafHttpContext, ok := r.Context().Value("waf_context").(innerbean.WafHttpContextData); ok {

			backendCheckStart := time.Now().UnixNano() / 1e6

			weblogfrist := wafHttpContext.Weblog

			host := waf.HostCode[wafHttpContext.HostCode]
			weblogfrist.ACTION = "放行"
			weblogfrist.STATUS = resp.Status
			weblogfrist.STATUS_CODE = resp.StatusCode

			ldpFlag := false
			//隐私保护（局部）
			for i := 0; i < len(waf.HostTarget[host].LdpUrlLists); i++ {
				if (waf.HostTarget[host].LdpUrlLists[i].CompareType == "等于" && waf.HostTarget[host].LdpUrlLists[i].Url == resp.Request.RequestURI) ||
					(waf.HostTarget[host].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(resp.Request.RequestURI, waf.HostTarget[host].LdpUrlLists[i].Url)) ||
					(waf.HostTarget[host].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(resp.Request.RequestURI, waf.HostTarget[host].LdpUrlLists[i].Url)) ||
					(waf.HostTarget[host].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(resp.Request.RequestURI, waf.HostTarget[host].LdpUrlLists[i].Url)) {

					ldpFlag = true
					break
				}
			}
			//隐私保护（局部）
			for i := 0; i < len(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists); i++ {
				if (waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "等于" && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url == resp.Request.RequestURI) ||
					(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(resp.Request.RequestURI, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)) ||
					(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(resp.Request.RequestURI, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)) ||
					(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(resp.Request.RequestURI, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)) {

					ldpFlag = true
					break
				}
			}
			if ldpFlag == true {
				orgContentBytes, _ := waf.getOrgContent(resp)
				newPayload := []byte("" + utils.DeSenText(string(orgContentBytes)))
				finalCompressBytes, _ := waf.compressContent(resp, newPayload)

				resp.Body = io.NopCloser(bytes.NewBuffer(finalCompressBytes))
				// head 修改追加内容
				resp.ContentLength = int64(len(finalCompressBytes))
				resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalCompressBytes)), 10))
			}
			//返回内容的类型
			respContentType := resp.Header.Get("Content-Type")
			respContentType = strings.Replace(respContentType, "; charset=utf-8", "", -1)

			//记录静态日志
			isStaticAssist := utils.IsStaticAssist(respContentType)
			isText := utils.IsContent(respContentType)

			//记录响应body
			if isText && resp.Body != nil && resp.Body != http.NoBody {

				//编码转换，自动检测网页编码   resp *http.Response
				orgContentBytes, _ := waf.getOrgContent(resp)

				if global.GCONFIG_RECORD_RESP == 1 {
					if resp.ContentLength < global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH {
						weblogfrist.RES_BODY = string(orgContentBytes)
						weblogfrist.SrcByteResBody = orgContentBytes
					}
				}

				//处理敏感词
				if waf.CheckResponseSensitive() {
					//敏感词检测
					matchBodyResult := waf.SensitiveManager.MultiPatternSearch([]rune(string(orgContentBytes)), false)
					if len(matchBodyResult) > 0 {
						sensitive := matchBodyResult[0].CustomData.(model.Sensitive)

						if sensitive.CheckDirection != "in" {
							weblogfrist.RISK_LEVEL = 1
							if sensitive.Action == "deny" {
								EchoResponseErrorInfo(resp, *weblogfrist, "敏感词检测："+string(matchBodyResult[0].Word), "敏感词内容", waf.HostTarget[host], waf.HostTarget[waf.HostCode[global.GWAF_GLOBAL_HOST_CODE]], true)
								return nil

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

				finalCompressBytes, _ := waf.compressContent(resp, orgContentBytes)
				resp.Body = io.NopCloser(bytes.NewBuffer(finalCompressBytes))

				// head 修改追加内容
				resp.ContentLength = int64(len(finalCompressBytes))
				resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalCompressBytes)), 10))

			}
			zlog.Debug("TESTChanllage", weblogfrist.HOST, weblogfrist.URL)
			if !isStaticAssist {
				datetimeNow := time.Now()
				weblogfrist.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME

				if strings.HasPrefix(weblogfrist.URL, global.GSSL_HTTP_CHANGLE_PATH) && (resp.StatusCode == 404 || resp.StatusCode == 302) {
					//如果远端HTTP01不存在挑战验证文件，那么我们映射到走本地再试一下

					//Challenge /.well-known/acme-challenge/2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8
					urls := strings.Split(weblogfrist.URL, "/")
					if len(urls) == 4 {
						challengeFile := urls[3]
						//检测challengeFile是否合法
						if !utils.IsValidChallengeFile(challengeFile) {
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

							weblogfrist.ACTION = "放行"
							weblogfrist.STATUS = resp.Status
							weblogfrist.STATUS_CODE = resp.StatusCode
							weblogfrist.TASK_FLAG = 1
							weblogfrist.BackendCheckCost = time.Now().UnixNano()/1e6 - backendCheckStart //响应数据处理时间
							global.GQEQUE_LOG_DB.Enqueue(weblogfrist)
						}
					}
				} else {
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

// 返回内容前依据情况进行返回压缩数据
func (waf *WafEngine) compressContent(res *http.Response, inputBytes []byte) (respBytes []byte, err error) {

	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		respBytes, err = utils.GZipEncode(inputBytes)
	case "deflate":
		respBytes, err = utils.DeflateEncode(inputBytes)
	default:
		respBytes = inputBytes
	}
	return
}

// 获取原始内容
func (waf *WafEngine) getOrgContent(resp *http.Response) (cntBytes []byte, err error) {
	var bodyReader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		bodyReader, err = gzip.NewReader(resp.Body)
	case "deflate":
		bodyReader = flate.NewReader(resp.Body)
	default:
		bodyReader = resp.Body
	}
	newBodyReader := bufio.NewReader(bodyReader)
	//使用peek读取十分关键，只是偷看一下，不会移动读取位置，否则其他地方就没法读取了
	var currentEncoding encoding.Encoding
	bytes, err := newBodyReader.Peek(1024)
	if err != nil {
		currentEncoding = unicode.UTF8
	} else {
		currentEncoding, _, _ = charset.DetermineEncoding(bytes, resp.Header.Get("Content-Type"))
	}
	reader := transform.NewReader(newBodyReader, currentEncoding.NewDecoder())
	resbodyByte, err := io.ReadAll(reader)
	if err != nil {
		zlog.Info("error", err)
		return nil, err
	}
	return resbodyByte, nil
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
			Code:             uuid.NewV4().String(),
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

	wafSysLog := &model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "信息",
		OpContent: "WAF启动",
	}
	global.GQEQUE_LOG_DB.Enqueue(wafSysLog)

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
			Id:          uuid.NewV4().String(),
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
	waf.ServerOnline = map[int]innerbean.ServerRunTime{}
	waf.AllCertificate = AllCertificate{
		Mux: sync.Mutex{},
		Map: map[string]*tls.Certificate{},
	}
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

	for _, v := range waf.ServerOnline {
		waf.StartProxyServer(v)
	}
	waf.EnumAllPortProxyServer()

	waf.ReLoadSensitive()
}

// 罗列端口
func (waf *WafEngine) EnumAllPortProxyServer() {
	onlinePorts := ""
	for _, v := range waf.ServerOnline {
		onlinePorts = strconv.Itoa(v.Port) + "," + onlinePorts
	}
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
			svr := &http.Server{
				Addr:    ":" + strconv.Itoa(innruntime.Port),
				Handler: waf,
				TLSConfig: &tls.Config{
					GetCertificate: waf.GetCertificateFunc,
				},
			}
			serclone := waf.ServerOnline[innruntime.Port]
			serclone.Svr = svr
			serclone.Status = 0
			waf.ServerOnline[innruntime.Port] = serclone
			zlog.Info("启动HTTPS 服务器" + strconv.Itoa(innruntime.Port))
			err := svr.ListenAndServeTLS("", "")
			if err == http.ErrServerClosed {
				zlog.Error("[HTTPServer] https server has been close, cause:[%v]", err)
			} else {
				//TODO 记录如果https 端口被占用的情况 记录日志 且应该推送websocket
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.NewV4().String(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "系统运行错误",
					OpContent: "HTTPS端口被占用: " + strconv.Itoa(innruntime.Port) + ",请检查",
				}
				global.GQEQUE_LOG_DB.Enqueue(wafSysLog)
				zlog.Error("[HTTPServer] https server start fail, cause:[%v]", err)
			}
			zlog.Info("server https shutdown")

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
			serclone := waf.ServerOnline[innruntime.Port]
			serclone.Svr = svr
			serclone.Status = 0

			waf.ServerOnline[innruntime.Port] = serclone

			zlog.Info("启动HTTP 服务器" + strconv.Itoa(innruntime.Port))
			err := svr.ListenAndServe()
			if err == http.ErrServerClosed {
				zlog.Warn("[HTTPServer] http server has been close, cause:[%v]", err)
			} else {
				//TODO 记录如果http 端口被占用的情况 记录日志 且应该推送websocket
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.NewV4().String(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "系统运行错误",
					OpContent: "HTTP端口被占用: " + strconv.Itoa(innruntime.Port) + ",请检查",
				}
				global.GQEQUE_LOG_DB.Enqueue(wafSysLog)
				zlog.Error("[HTTPServer] http server start fail, cause:[%v]", err)
			}
			zlog.Info("server  http shutdown")
		}

	}(innruntime)
}

// 关闭所有代理服务
func (waf *WafEngine) StopAllProxyServer() {
	for _, v := range waf.ServerOnline {
		waf.StopProxyServer(v)
	}
}

// 关闭指定代理服务
func (waf *WafEngine) StopProxyServer(v innerbean.ServerRunTime) {
	if v.Svr != nil {
		v.Svr.Close()
	}
}
