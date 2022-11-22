package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"golang.org/x/time/rate"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 主机安全配置
type HostSafe struct {
	RevProxy            *httputil.ReverseProxy
	Rule                *utils.RuleHelper
	TargetHost          string
	RuleData            []model.Rules
	RuleVersionSum      int //规则版本的汇总 通过这个来进行版本动态加载
	Host                model.Hosts
	pluginIpRateLimiter *plugin.IPRateLimiter //ip限流
}

var (
	//主机情况
	hostTarget = map[string]*HostSafe{}
	//主机和code的关系
	hostCode     = map[string]string{}
	ipcBuff      = []byte{} //ip数据
	serverOnline = map[int]innerbean.ServerRunTime{}

	//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
	allCertificate = map[int]map[string]*tls.Certificate{}
	//allCertificate = map[int] map[string] string{}
	esHelper utils.EsHelper

	phttphandler *baseHandle
	hostRuleChan = make(chan []model.Rules, 10) //规则链
	//engineChan   = make(chan int, 10)           //引擎链
	//hostChan                                  = make(chan model.Hosts, 10)   //主机链
	engineCurrentStatus int = 0 // 当前waf引擎状态

)

type baseHandle struct{}

func GetCountry(ip string) []string {
	// 2、用全局的 cBuff 创建完全基于内存的查询对象。
	searcher, err := xdb.NewWithBuffer(ipcBuff)
	if err != nil {
		fmt.Printf("failed to create searcher with content: %s\n", err)

	}

	defer searcher.Close()

	// do the search
	var tStart = time.Now()

	// 备注：并发使用，每个 goroutine 需要创建一个独立的 searcher 对象。
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return []string{"无", "无"}
	}

	zlog.Debug("{region: %s, took: %s}\n", region, time.Since(tStart))
	regions := strings.Split(region, "|")

	return regions
	/*if regions[0] == "中国" {
		return true
	} else if regions[0] == "0" {
		return true
	} else {
		return false
	}*/
}
func customResult(w http.ResponseWriter, r *http.Request, webLog innerbean.WebLog) {

}
func (h *baseHandle) Error() string {
	fs := "HTTP: %d, HostCode: %d, Message: %s"
	return fmt.Sprintf(fs)
}
func (h *baseHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			fmt.Println("11recover ", e)
		}
	}()
	// 获取请求报文的内容长度
	contentLength := r.ContentLength

	//server_online[8081].Svr.Close()
	var bodyByte []byte

	// 拷贝一份request的Body
	if r.Body != nil {
		bodyByte, _ = io.ReadAll(r.Body)
		// 把刚刚读出来的再写进去，不然后面解析表单数据就解析不到了
		r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
	}
	cookies, _ := json.Marshal(r.Cookies())
	header, _ := json.Marshal(r.Header)
	// 取出客户IP
	ipAndPort := strings.Split(r.RemoteAddr, ":")
	region := GetCountry(ipAndPort[0])
	currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))
	weblogbean := innerbean.WebLog{
		HOST:           host,
		URL:            r.RequestURI,
		REFERER:        r.Referer(),
		USER_AGENT:     r.UserAgent(),
		METHOD:         r.Method,
		HEADER:         string(header),
		COUNTRY:        region[0],
		PROVINCE:       region[2],
		CITY:           region[3],
		SRC_IP:         ipAndPort[0],
		SRC_PORT:       ipAndPort[1],
		CREATE_TIME:    time.Now().Format("2006-01-02 15:04:05"),
		CONTENT_LENGTH: contentLength,
		COOKIES:        string(cookies),
		BODY:           string(bodyByte),
		REQ_UUID:       uuid.NewV4().String(),
		USER_CODE:      global.GWAF_USER_CODE,
		HOST_CODE:      hostTarget[host].Host.Code,
		TenantId:       global.GWAF_TENANT_ID,
		RULE:           "",
		ACTION:         "通过",
		Day:            currentDay,
	}

	if hostTarget[host].Host.GUARD_STATUS == 1 {

		//cc 防护
		limiter := hostTarget[host].pluginIpRateLimiter.GetLimiter(weblogbean.SRC_IP)
		if !limiter.Allow() {
			weblogbean.RULE = "触发IP频次访问限制"
			weblogbean.ACTION = "阻止"
			global.GWAF_LOCAL_DB.Create(weblogbean)
			w.Write([]byte("<html><head><title>您的访问被阻止</title></head><body><center><h1>您的访问被阻止超量了</h1> <br> 访问识别码：<h3>" + weblogbean.REQ_UUID + "</h3></center></body> </html>"))
			zlog.Debug("已经被限制访问了")
			return
		}

		ruleMatchs, err := hostTarget[host].Rule.Match("MF", &weblogbean)
		if err == nil {
			if len(ruleMatchs) > 0 {

				rulestr := ""
				for _, v := range ruleMatchs {
					rulestr = rulestr + v.RuleDescription + ","
				}
				weblogbean.RULE = rulestr
				weblogbean.ACTION = "阻止"
				global.GWAF_LOCAL_DB.Create(weblogbean)

				w.Header().Set("WAF", "SAMWAF DROP")
				/*expiration := time.Now()
				expiration = expiration.AddDate(1, 0, 0)
				cookie := http.Cookie{Name: "IDENFY", Value: weblogbean.REQ_UUID, Expires: expiration}
				http.SetCookie(w, &cookie)*/
				w.Write([]byte("<html><head><title>您的访问被阻止</title></head><body><center><h1>您的访问被阻止</h1> <br> 访问识别码：<h3>" + weblogbean.REQ_UUID + "</h3></center></body> </html>"))

				return
			}
		} else {
			zlog.Debug("规则 ", err)
		}
	}
	// 取出代理ip

	// 直接从缓存取出
	if hostTarget[host].RevProxy != nil {
		weblogbean.ACTION = "放行"
		global.GWAF_LOCAL_DB.Create(weblogbean)
		hostTarget[host].RevProxy.ServeHTTP(w, r)
		return
	}

	// 检查域名白名单
	if target, ok := hostTarget[host]; ok {
		remoteUrl, err := url.Parse(target.TargetHost)
		if err != nil {
			zlog.Debug("target parse fail:", zap.Any("", err))
			return
		}

		// 直接从缓存取出
		if hostTarget[host].RevProxy != nil {
			hostTarget[host].RevProxy.ServeHTTP(w, r)
		} else {
			proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
			proxy.ModifyResponse = modifyResponse()
			proxy.ErrorHandler = errorHandler()
			hostTarget[host].RevProxy = proxy // 放入缓存
			proxy.ServeHTTP(w, r)
		}
		weblogbean.ACTION = "放行"
		global.GWAF_LOCAL_DB.Create(weblogbean)
		return
	} else {
		w.Write([]byte("403: Host forbidden " + host))
		weblogbean.ACTION = "禁止"
		global.GWAF_LOCAL_DB.Create(weblogbean)
	}
}
func errorHandler() func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, req *http.Request, err error) {
		zlog.Debug("Got error  response:", zap.Any("err", err))
		return
	}
}

func modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		resp.Header.Set("WAF", "SamWAF")
		zlog.Debug("%s %s", resp.Request.Host, resp.Request.RequestURI)
		if resp.StatusCode != 200 {
			//获取内容
			oldPayload, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			// body 追加内容
			newPayload := []byte("" + string(oldPayload))
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(newPayload))

			// head 修改追加内容
			resp.ContentLength = int64(len(newPayload))
			resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(newPayload)), 10))
		} else {
			//特定网站和请求url需要特定处理
			if resp.Request.Host == "mybaidu1.com:8082" && resp.Request.RequestURI == "/admin.php/user/agent_user/edit/id/73.html" {

				//编码转换，自动检测网页编码
				convertCntReader, _ := switchContentEncoding(resp)
				bodyReader := bufio.NewReader(convertCntReader)
				charset := determinePageEncoding(bodyReader)

				reader := transform.NewReader(bodyReader, charset.NewDecoder())
				oldBytes, err := io.ReadAll(reader)
				if err != nil {
					zlog.Error("error", err)
					return nil
				}

				// body 追加内容
				//zlog.Debug(string(oldBytes))
				//newPayload := []byte("" +  strings.Replace(string(oldBytes), "青岛", "**", -1))
				newPayload := []byte("" + utils.DeSenText(string(oldBytes)))

				finalBytes, _ := switchReplyContentEncoding(resp, newPayload) //utils.GZipEncode(newPayload)
				//zlog.Debug("转换完",string(finalBytes))
				resp.Body = io.NopCloser(bytes.NewBuffer(finalBytes))

				// head 修改追加内容
				resp.ContentLength = int64(len(newPayload))
				resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(finalBytes)), 10))
			}
		}

		return nil
	}
}

// 返回是否需要进行压缩

func switchReplyContentEncoding(res *http.Response, inputBytes []byte) (respBytes []byte, err error) {

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

// 检测返回的body是否经过压缩，并返回解压的内容
func switchContentEncoding(res *http.Response) (bodyReader io.Reader, err error) {
	switch res.Header.Get("Content-Encoding") {
	case "gzip":
		bodyReader, err = gzip.NewReader(res.Body)
	case "deflate":
		bodyReader = flate.NewReader(res.Body)
	default:
		bodyReader = res.Body
	}
	return
}

// 检测html页面编码
func determinePageEncoding(r *bufio.Reader) encoding.Encoding {
	//使用peek读取十分关键，只是偷看一下，不会移动读取位置，否则其他地方就没法读取了
	bytes, err := r.Peek(1024)
	if err != nil {
		log.Printf("Fetcher error: %v\n", err)
		return unicode.UTF8
	}
	e, _, _ := charset.DetermineEncoding(bytes, "")
	return e
}
func Start_WAF() {
	config := viper.New()
	config.AddConfigPath("./conf/") // 文件所在目录
	config.SetConfigName("config")  // 文件名
	config.SetConfigType("yml")     // 文件类型
	engineCurrentStatus = 1
	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			zlog.Error("找不到配置文件..")
		} else {
			zlog.Error("配置文件出错..")
		}
	}

	global.GWAF_USER_CODE = config.GetString("user_code") // 读取配置
	global.GWAF_TENANT_ID = global.GWAF_USER_CODE
	global.GWAF_LOCAL_SERVER_PORT = config.GetInt("local_port") //读取本地端口
	zlog.Debug(" load ini: ", global.GWAF_USER_CODE)

	var hosts []model.Hosts

	global.GWAF_LOCAL_DB.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Where("user_code = ?", global.GWAF_USER_CODE).Find(&hosts)

	//初始化步骤[加载ip数据库]
	var dbPath = "data/ip2region.xdb"
	// 1、从 dbPath 加载整个 xdb 到内存
	cBuff, err := xdb.LoadContentFromFile(dbPath)
	if err != nil {
		zlog.Info("加载ip库错误")
		zlog.Debug("failed to load content from `%s`: %s\n", dbPath, err)
		return
	}
	ipcBuff = cBuff

	//第一步 检测合法性并加入到全局
	for i := 0; i < len(hosts); i++ {
		//检测https
		if hosts[i].Ssl == 1 {
			cert, err := tls.X509KeyPair([]byte(hosts[i].Certfile), []byte(hosts[i].Keyfile))
			if err != nil {
				zlog.Warn("Cannot find %s cert & key file. Error is: %s\n", hosts[i].Host, err)
				continue

			}
			//all_certificate[hosts[i].Port][hosts[i].Host] = &cert
			mm, ok := allCertificate[hosts[i].Port] //[hosts[i].Host]
			if !ok {
				mm = make(map[string]*tls.Certificate)
				allCertificate[hosts[i].Port] = mm
			}
			allCertificate[hosts[i].Port][hosts[i].Host] = &cert
		}
		_, ok := serverOnline[hosts[i].Port]
		if ok == false {
			serverOnline[hosts[i].Port] = innerbean.ServerRunTime{
				ServerType: utils.GetServerByHosts(hosts[i]),
				Port:       hosts[i].Port,
				Status:     0,
			}
		}

		//加载主机对于的规则
		ruleHelper := &utils.RuleHelper{}

		//查询规则
		//TODO 未加租户ID
		var vcnt int
		global.GWAF_LOCAL_DB.Debug().Model(&model.Rules{}).Where("host_code = ? and user_code=? ",
			hosts[i].Code, global.GWAF_USER_CODE).Select("sum(rule_version) as vcnt").Row().Scan(&vcnt)
		zlog.Debug("主机host" + hosts[i].Code + " 版本" + strconv.Itoa(vcnt))
		var ruleconfigs []model.Rules
		if vcnt > 0 {
			global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and user_code=? ", hosts[i].Code, global.GWAF_USER_CODE).Find(&ruleconfigs)
			ruleHelper.LoadRules(ruleconfigs)
		}
		//查询ip限流(应该针对一个网址只有一个)
		var anticcBean model.AntiCC

		global.GWAF_LOCAL_DB.Where("host_code=? ", hosts[i].Code).Limit(1).Find(&anticcBean)

		//初始化插件-ip计数器
		var pluginIpRateLimiter *plugin.IPRateLimiter
		if anticcBean.Id != "" {
			pluginIpRateLimiter = plugin.NewIPRateLimiter(rate.Limit(anticcBean.Rate), anticcBean.Limit)
		}

		hostsafe := &HostSafe{
			RevProxy:            nil,
			Rule:                ruleHelper,
			TargetHost:          hosts[i].Remote_host + ":" + strconv.Itoa(hosts[i].Remote_port),
			RuleData:            ruleconfigs,
			RuleVersionSum:      vcnt,
			Host:                hosts[i],
			pluginIpRateLimiter: pluginIpRateLimiter,
		}
		//赋值到白名单里面
		hostTarget[hosts[i].Host+":"+strconv.Itoa(hosts[i].Port)] = hostsafe
		//赋值到对照表里面
		hostCode[hosts[i].Code] = hosts[i].Host + ":" + strconv.Itoa(hosts[i].Port)

	}
	for _, v := range serverOnline {
		go func(innruntime innerbean.ServerRunTime) {

			if (innruntime.ServerType) == "https" {

				svr := &http.Server{
					Addr:    ":" + strconv.Itoa(innruntime.Port),
					Handler: phttphandler,
					TLSConfig: &tls.Config{
						NameToCertificate: make(map[string]*tls.Certificate, 0),
					},
				}
				serclone := serverOnline[innruntime.Port]
				serclone.Svr = svr
				serverOnline[innruntime.Port] = serclone

				svr.TLSConfig.NameToCertificate = allCertificate[innruntime.Port]
				svr.TLSConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if x509Cert, ok := svr.TLSConfig.NameToCertificate[clientInfo.ServerName]; ok {
						return x509Cert, nil
					}
					return nil, errors.New("config error")
				}
				zlog.Info("启动HTTPS 服务器" + strconv.Itoa(innruntime.Port))
				err = svr.ListenAndServeTLS("", "")
				if err == http.ErrServerClosed {
					zlog.Info("[HTTPServer] https server has been close, cause:[%v]", err)
				} else {
					zlog.Error("[HTTPServer] https server start fail, cause:[%v]", err)
				}
				zlog.Info("server https shutdown")

			} else {
				defer func() {
					e := recover()
					if e != nil { // 捕获该协程的panic 111111
						zlog.Warn("recover ", e)
					}
				}()
				svr := &http.Server{
					Addr:    ":" + strconv.Itoa(innruntime.Port),
					Handler: phttphandler,
				}
				serclone := serverOnline[innruntime.Port]
				serclone.Svr = svr
				serverOnline[innruntime.Port] = serclone

				zlog.Info("启动HTTP 服务器" + strconv.Itoa(innruntime.Port))
				err = svr.ListenAndServe()
				if err == http.ErrServerClosed {
					zlog.Warn("[HTTPServer] http server has been close, cause:[%v]", err)
				} else {
					zlog.Error("[HTTPServer] http server start fail, cause:[%v]", err)
				}
				zlog.Info("server  http shutdown")
			}

		}(v)

	}
}

// 关闭waf
func CLoseWAF() {
	defer func() {
		e := recover()
		if e != nil { // 捕获该协程的panic 111111
			zlog.Debug("关闭 recover ", e)
		}
	}()
	engineCurrentStatus = 0
	for _, v := range serverOnline {
		if v.Svr != nil {
			v.Svr.Close()
		}
	}

	//重置信息

	hostTarget = map[string]*HostSafe{}
	hostCode = map[string]string{}
	serverOnline = map[int]innerbean.ServerRunTime{}
	allCertificate = map[int]map[string]*tls.Certificate{}

}
