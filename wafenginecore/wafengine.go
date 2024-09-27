package wafenginecore

import (
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/plugin"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/wafenginecore/loadbalance"
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
	goahocorasick "github.com/anknown/ahocorasick"
	"github.com/satori/go.uuid"
	"go.uber.org/zap"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type WafEngine struct {
	//主机情况（key:主机名+":"+端口,value : hostsafe信息里面有规则,ip信息等）
	HostTarget map[string]*wafenginmodel.HostSafe
	//主机和code的关系（key:主机code,value:主机名+":"+端口）
	HostCode map[string]string
	//服务在线情况（key：端口，value :服务情况）
	ServerOnline map[int]innerbean.ServerRunTime

	//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
	//嵌套结构 (key：端口 ，再往下是 下面的主机名，value 证书)
	AllCertificate map[int]map[string]*tls.Certificate

	EngineCurrentStatus int // 当前waf引擎状态

	//敏感词管理
	Sensitive        []model.Sensitive //敏感词
	SensitiveManager *goahocorasick.Machine
}

func (waf *WafEngine) Error() string {
	fs := "HTTP: %d, HostCode: %d, Message: %s"
	return fmt.Sprintf(fs)
}
func (waf *WafEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		}
	}()
	// 检查域名是否已经注册
	if target, ok := waf.HostTarget[host]; ok {
		// 取出客户IP
		ipErr, clientIP, clientPort := waf.getClientIP(r, strings.Split(global.GCONFIG_RECORD_PROXY_HEADER, ",")...)
		if ipErr != nil {
			zlog.Error("get client error", ipErr.Error())
			return
		}
		_, ok := waf.ServerOnline[waf.HostTarget[host].Host.Remote_port]
		//检测如果访问IP和远程IP是同一个IP，且远程端口在本地Server已存在则显示配置错误
		if clientIP == waf.HostTarget[host].Host.Remote_ip && ok == true {
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
		enEscapeUrl, _urlEscapeOk := url.QueryUnescape(r.RequestURI)
		if _urlEscapeOk != nil {
			enEscapeUrl = r.RequestURI
		}
		datetimeNow := time.Now()
		weblogbean := innerbean.WebLog{
			HOST:                 host,
			URL:                  enEscapeUrl,
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
			HOST_CODE:            waf.HostTarget[host].Host.Code,
			TenantId:             global.GWAF_TENANT_ID,
			RULE:                 "",
			ACTION:               "通过",
			Day:                  currentDay,
			POST_FORM:            r.PostForm.Encode(),
			TASK_FLAG:            -1,
			RISK_LEVEL:           0,      //危险等级
			GUEST_IDENTIFICATION: "正常访客", //访客身份识别
			TimeSpent:            0,
		}

		formValues := url.Values{}
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			// 解码 x-www-form-urlencoded 数据
			formValuest, err := url.ParseQuery(weblogbean.BODY)
			if err != nil {
				fmt.Println("解码失败:", err)
			} else {
				formValues = formValuest
			}
		}

		r.Header.Add("waf_req_uuid", weblogbean.REQ_UUID)

		if waf.HostTarget[host].Host.GUARD_STATUS == 1 {
			//一系列检测逻辑
			handleBlock := func(checkFunc func(*innerbean.WebLog, url.Values) detection.Result) bool {
				detectionResult := checkFunc(&weblogbean, formValues)
				if detectionResult.IsBlock {
					EchoErrorInfo(w, r, weblogbean, detectionResult.Title, detectionResult.Content)
					return true
				}
				return false
			}
			detectionResult := waf.CheckAllowIP(&weblogbean, formValues)
			detectionResult = waf.CheckAllowURL(weblogbean, formValues)

			if detectionResult.JumpGuardResult == false {

				if handleBlock(waf.CheckDenyIP) {
					return
				}
				if handleBlock(waf.CheckDenyURL) {
					return
				}

				hostDefense := model.HostsDefense{
					DEFENSE_BOT:       1,
					DEFENSE_SQLI:      1,
					DEFENSE_XSS:       1,
					DEFENSE_SCAN:      1,
					DEFENSE_RCE:       1,
					DEFENSE_SENSITIVE: 1,
				}
				err := json.Unmarshal([]byte(waf.HostTarget[host].Host.DEFENSE_JSON), &hostDefense)
				if err != nil {
					zlog.Error("解析defense json失败")
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

			}

		}
		// 日志保存时候也是脱敏保存防止，数据库密码被破解，遭到敏感信息遭到泄露
		if weblogbean.BODY != "" {
			weblogbean.BODY = utils.DeSenTextByCustomMark(enums.DLP_MARK_RULE_LoginSensitiveInfoMaskRule, weblogbean.BODY)
		}
		remoteUrl, err := url.Parse(target.TargetHost)
		if err != nil {
			zlog.Debug("target parse fail:", zap.Any("", err))
			return
		}
		// 在请求上下文中存储自定义数据
		ctx := context.WithValue(r.Context(), "weblog", weblogbean)
		// 代理请求
		waf.ProxyHTTP(w, r, host, remoteUrl, clientIP, ctx, weblogbean)
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
		}

		//记录响应body
		weblogbean.RES_BODY = string(resBytes)
		weblogbean.ACTION = "禁止"
		global.GQEQUE_LOG_DB.PushBack(weblogbean)
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
			return errors.New("invalid IPv4 address from header: " + header + " value:" + ip), "", ""
		}
	}

	// 如果没有找到，使用 r.RemoteAddr
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err, "", ""
	}
	if !utils.IsValidIPv4(ip) {
		return errors.New("invalid IPv4 address from RemoteAddr" + " value:" + ip), "", ""
	}

	return nil, ip, port
}
func EchoErrorInfo(w http.ResponseWriter, r *http.Request, weblogbean innerbean.WebLog, ruleName string, blockInfo string) {
	//发送微信推送消息
	global.GQEQUE_MESSAGE_DB.PushBack(innerbean.RuleMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: global.GWAF_CUSTOM_SERVER_NAME},
		Domain:          weblogbean.HOST,
		RuleInfo:        ruleName,
		Ip:              fmt.Sprintf("%s (%s)", weblogbean.SRC_IP, utils.GetCountry(weblogbean.SRC_IP)),
	})

	resBytes := []byte("<html><head><title>您的访问被阻止</title></head><body><center><h1>" + blockInfo + "</h1> <br> 访问识别码：<h3>" + weblogbean.REQ_UUID + "</h3></center></body> </html>")
	w.WriteHeader(403)
	_, err := w.Write(resBytes)
	if err != nil {
		zlog.Debug("write fail:", zap.Any("", err))
		return
	}
	datetimeNow := time.Now()
	weblogbean.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
	//记录响应body
	weblogbean.RES_BODY = string(resBytes)
	weblogbean.RULE = ruleName
	weblogbean.ACTION = "阻止"
	weblogbean.STATUS = "阻止访问"
	weblogbean.STATUS_CODE = 403
	weblogbean.TASK_FLAG = 1
	weblogbean.GUEST_IDENTIFICATION = "可疑用户"
	global.GQEQUE_LOG_DB.PushBack(weblogbean)
}
func (waf *WafEngine) errorResponse() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		zlog.Error("服务不可用 response:", zap.Any("err", err))
		resBytes := []byte("<html><head><title>服务不可用</title></head><body><center><h1>服务不可用</h1> <br><h3></h3></center></body> </html>")

		w.WriteHeader(http.StatusServiceUnavailable)
		if _, writeErr := w.Write(resBytes); writeErr != nil {
			zlog.Debug("write fail:", zap.Any("err", writeErr))
			return
		}

		return
	}
}
func (waf *WafEngine) modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		resp.Header.Set("WAF", "SamWAF")
		resp.Header.Set("Server", "SamWAFServer")
		resp.Header.Set("X-Xss-Protection", "1; mode=block")

		r := resp.Request

		if weblogfrist, ok := r.Context().Value("weblog").(innerbean.WebLog); ok {
			fmt.Sprintf("weblogfrist: %v", weblogfrist)

			weblogfrist.ACTION = "放行"
			weblogfrist.STATUS = resp.Status
			weblogfrist.STATUS_CODE = resp.StatusCode

			host := resp.Request.Host
			if !strings.Contains(host, ":") {
				// 检查请求是否使用了HTTPS
				if resp.Request.TLS != nil {
					// 请求使用了HTTPS
					host = host + ":443"
				} else {
					// 请求使用了HTTP
					host = host + ":80"
				}
			}

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
			contentType := ""
			//JS情况
			if respContentType == "application/javascript" {
				contentType = "js"
			}
			//CSS情况
			if respContentType == "text/css" {
				contentType = "css"
			}
			//图片情况
			if respContentType == "image/jpeg" || respContentType == "image/png" ||
				respContentType == "image/gif" || respContentType == "image/x-icon" {
				contentType = "img"
			}
			//文本资源
			if respContentType == "text/html" || respContentType == "application/html" ||
				respContentType == "application/json" || respContentType == "application/xml" {
				contentType = "text"
			}
			//记录静态日志
			isStaticAssist := false
			isText := false
			switch contentType {
			case "js":
				isStaticAssist = true
				break
			case "css":
				isStaticAssist = true
				break
			case "img":
				isStaticAssist = true
				break
			case "text":
				isText = true
				break
			default:
				/*weblogbean.ACTION = "放行"
				global.GQEQUE_LOG_DB.PushBack(weblogbean)*/
			}

			//记录响应body
			if isText && resp.Body != nil && resp.Body != http.NoBody && global.GCONFIG_RECORD_RESP == 1 {

				//编码转换，自动检测网页编码
				orgContentBytes, _ := waf.getOrgContent(resp)
				finalCompressBytes, _ := waf.compressContent(resp, orgContentBytes)
				resp.Body = io.NopCloser(bytes.NewBuffer(finalCompressBytes))

				// head 修改追加内容
				resp.ContentLength = int64(len(finalCompressBytes))
				resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalCompressBytes)), 10))
				if resp.ContentLength < global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH {
					weblogfrist.RES_BODY = string(orgContentBytes)
				}
			}

			if !isStaticAssist {
				datetimeNow := time.Now()
				weblogfrist.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogfrist.UNIX_ADD_TIME
				weblogfrist.ACTION = "放行"
				weblogfrist.STATUS = resp.Status
				weblogfrist.STATUS_CODE = resp.StatusCode
				weblogfrist.TASK_FLAG = 1
				if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
					if waf.HostTarget[host].Host.EXCLUDE_URL_LOG == "" {
						global.GQEQUE_LOG_DB.PushBack(weblogfrist)
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
							global.GQEQUE_LOG_DB.PushBack(weblogfrist)
						}
					}
				} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblogfrist.ACTION != "放行" {
					global.GQEQUE_LOG_DB.PushBack(weblogfrist)
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
		currentEncoding, _, _ = charset.DetermineEncoding(bytes, "")
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
			Code:          uuid.NewV4().String(),
			Host:          "全局网站",
			Port:          0,
			Ssl:           0,
			GUARD_STATUS:  0,
			REMOTE_SYSTEM: "",
			REMOTE_APP:    "",
			Remote_host:   "",
			Remote_port:   0,
			Certfile:      "",
			Keyfile:       "",
			REMARKS:       "",
			GLOBAL_HOST:   1,
			START_STATUS:  0,
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
	global.GQEQUE_LOG_DB.PushBack(wafSysLog)

	waf.StartAllProxyServer()
}

// 关闭waf
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
	global.GQEQUE_LOG_DB.PushBack(wafSysLog)
	waf.EngineCurrentStatus = 0

	waf.StopAllProxyServer()
	//重置信息
	waf.HostTarget = map[string]*wafenginmodel.HostSafe{}
	waf.HostCode = map[string]string{}
	waf.ServerOnline = map[int]innerbean.ServerRunTime{}
	waf.AllCertificate = map[int]map[string]*tls.Certificate{}

}

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
		cert, err := tls.X509KeyPair([]byte(inHost.Certfile), []byte(inHost.Keyfile))
		if err != nil {
			zlog.Warn("Cannot find %s cert & key file. Error is: %s\n", inHost.Host, err)
			return innerbean.ServerRunTime{}

		}
		mm, ok := waf.AllCertificate[inHost.Port] //[hosts[i].Host]
		if !ok {
			mm = make(map[string]*tls.Certificate)
			waf.AllCertificate[inHost.Port] = mm
		}
		waf.AllCertificate[inHost.Port][inHost.Host] = &cert
	}
	_, ok := waf.ServerOnline[inHost.Port]
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
	var pluginIpRateLimiter *plugin.IPRateLimiter
	if anticcBean.Id != "" {
		pluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(anticcBean.Rate), anticcBean.Limit)
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
	}
	hostsafe.Mux.Lock()
	defer hostsafe.Mux.Unlock()
	//赋值到白名单里面
	waf.HostTarget[inHost.Host+":"+strconv.Itoa(inHost.Port)] = hostsafe
	//赋值到对照表里面
	waf.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(inHost.Port)

	return waf.ServerOnline[inHost.Port]
}

/*
*
移除主机
*/
func (waf *WafEngine) RemoveHost(host model.Hosts, isSslChange bool) {
	/*//主机情况
	HostTarget map[string]*wafenginmodel.HostSafe
	//主机和code的关系
	HostCode     map[string]string
	ServerOnline map[int]innerbean.ServerRunTime

	//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
	AllCertificate map[int]map[string]*tls.Certificate*/
	//1.如果这个port里面没有了主机 那可以直接停掉服务
	//2.除了第一个情况之外的，把所有他的主机信息和关联信息都干掉

	if waf_service.WafHostServiceApp.CheckAvailablePortExistApi(host.Port) == 0 || isSslChange {
		zlog.Debug("准备移除这个端口下所有信息")
		// a.移除证书数据
		_, ok := waf.AllCertificate[host.Port]
		if ok {
			delete(waf.AllCertificate, host.Port)
		}
		//b.移除对照关系
		delete(waf.HostCode, host.Code)
		//c.移除主机保护信息
		delete(waf.HostTarget, host.Host+":"+strconv.Itoa(host.Port))
		//d.暂停服务 并 移除服务信息
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, svrOk := waf.ServerOnline[host.Port]
		if svrOk {
			err := waf.ServerOnline[host.Port].Svr.Shutdown(ctx)
			if err != nil {
				zlog.Error("shutting down: " + err.Error())
			} else {
				zlog.Info("shutdown processed successfully port" + strconv.Itoa(host.Port))
			}
			delete(waf.ServerOnline, host.Port)
		}

	} else {
		zlog.Debug("准备移除没用的主机信息")
		// a.移除某个端口下的证书数据
		_, ok := waf.AllCertificate[host.Port][host.Host]
		if ok {
			delete(waf.AllCertificate[host.Port], host.Host)
		}
		//b.移除对照关系
		delete(waf.HostCode, host.Code)
		//c.移除主机保护信息
		delete(waf.HostTarget, host.Host+":"+strconv.Itoa(host.Port))
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
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceRuntime.WeightRoundRobinBalance = &loadbalance.WeightRoundRobinBalance{}
		waf.HostTarget[waf.HostCode[hostCode]].LoadBalanceRuntime.IpHashBalance = loadbalance.NewConsistentHashBalance(nil)
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
					NameToCertificate: make(map[string]*tls.Certificate, 0),
				},
			}
			serclone := waf.ServerOnline[innruntime.Port]
			serclone.Svr = svr
			serclone.Status = 0
			waf.ServerOnline[innruntime.Port] = serclone

			svr.TLSConfig.NameToCertificate = waf.AllCertificate[innruntime.Port]
			svr.TLSConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if x509Cert, ok := svr.TLSConfig.NameToCertificate[clientInfo.ServerName]; ok {
					return x509Cert, nil
				}
				return nil, errors.New("config error")
			}
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
				global.GQEQUE_LOG_DB.PushBack(wafSysLog)
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
				global.GQEQUE_LOG_DB.PushBack(wafSysLog)
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
