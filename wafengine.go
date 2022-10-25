package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/plugin"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"io"
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
	RevProxy       *httputil.ReverseProxy
	Rule           *utils.RuleHelper
	TargetHost     string
	RuleData       []model.Rules
	RuleVersionSum int //规则版本的汇总 通过这个来进行版本动态加载
	Host           model.Hosts
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

	phttphandler        *baseHandle
	hostRuleChan                         = make(chan []model.Rules, 10) //规则链
	engineChan                           = make(chan int, 10)           //引擎链
	hostChan                             = make(chan model.Hosts, 10)   //主机链
	engineCurrentStatus int              = 0                            // 当前waf引擎状态
	pluginIpCounter     plugin.IpCounter                                //ip计数器

)

type baseHandle struct{}

func GetCountry(ip string) string {
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
		return "无"
	}

	fmt.Printf("{region: %s, took: %s}\n", region, time.Since(tStart))
	regions := strings.Split(region, "|")
	println(regions[0])
	return regions[0]
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
func CheckIP(ip string) bool {
	country := GetCountry(ip)
	if country == "中国" {
		return true
	} else if country == "0" {
		return true
	} else {
		return false
	}
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
	weblogbean := innerbean.WebLog{
		HOST:           host,
		URL:            r.RequestURI,
		REFERER:        r.Referer(),
		USER_AGENT:     r.UserAgent(),
		METHOD:         r.Method,
		HEADER:         string(header),
		COUNTRY:        GetCountry(ipAndPort[0]),
		SRC_IP:         ipAndPort[0],
		SRC_PORT:       ipAndPort[1],
		CREATE_TIME:    time.Now().Format("2006-01-02 15:04:05"),
		CONTENT_LENGTH: contentLength,
		COOKIES:        string(cookies),
		BODY:           string(bodyByte),
		REQ_UUID:       uuid.NewV4().String(),
		USER_CODE:      global.GWAF_USER_CODE,
		RULE:           "",
	}
	//ip计数器  TODO 应该是控制每分钟的访问次数，并且进行配置
	ipc := pluginIpCounter.Value(weblogbean.SRC_IP)
	if ipc != nil {
		if ipc.IpLockTime == 0 {
			pluginIpCounter.Lock(weblogbean.SRC_IP)
		}
		if time.Now().Unix()-ipc.IpLockTime > 60 { //超过60s释放
			pluginIpCounter.UnLock(weblogbean.SRC_IP)
		}
		if ipc.IpCnt > 1000 {
			w.Write([]byte("<html><head><title>您的访问被阻止</title></head><body><center><h1>您的访问被阻止超量了</h1> <br> 访问识别码：<h3>" + weblogbean.REQ_UUID + "</h3></center></body> </html>"))

			return
		}
	}
	pluginIpCounter.Inc(weblogbean.SRC_IP)

	//esHelper.BatchInsert("full_log", weblogbean)
	/*rule := &innerbean.WAF_REQUEST_FULL{
		SRC_INFO:   weblogbean,
		ExecResult: 0,
	}*/
	if hostTarget[host].Host.GUARD_STATUS == 1 {
		ruleMatchs, err := hostTarget[host].Rule.Match("MF", &weblogbean)
		if err == nil {
			if len(ruleMatchs) > 0 {

				rulestr := ""
				for _, v := range ruleMatchs {
					rulestr = rulestr + v.RuleDescription + ","
				}
				weblogbean.RULE = rulestr
				global.GWAF_LOCAL_DB.Create(weblogbean)

				zlog.Debug("no china")
				w.Header().Set("WAF", "SAMWAF DROP")
				/*expiration := time.Now()
				expiration = expiration.AddDate(1, 0, 0)
				cookie := http.Cookie{Name: "IDENFY", Value: weblogbean.REQ_UUID, Expires: expiration}
				http.SetCookie(w, &cookie)*/
				w.Write([]byte("<html><head><title>您的访问被阻止</title></head><body><center><h1>您的访问被阻止</h1> <br> 访问识别码：<h3>" + weblogbean.REQ_UUID + "</h3></center></body> </html>"))

				return
			}
		} else {
			fmt.Println("规则 ", err)
		}
	}
	// 取出代理ip

	// 直接从缓存取出
	if hostTarget[host].RevProxy != nil {
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

		proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
		proxy.ModifyResponse = modifyResponse()
		proxy.ErrorHandler = errorHandler()

		hostTarget[host].RevProxy = proxy // 放入缓存
		proxy.ServeHTTP(w, r)
		return
	} else {
		/*waflogbean := innerbean.WAFLog{
			CREATE_TIME: time.Now().Format("2006-01-02 15:04:05"),
			RULE:        hostTarget[host].RuleData.RuleName,
			ACTION:      "FORBIDDEN",
			REQ_UUID:    uuid.NewV4().String(),
			USER_CODE:   user_code,
		}*/
		//esHelper.BatchInsertWAF("web_log", waflogbean)
		w.Write([]byte("403: Host forbidden " + host))
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
		return nil
	}
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
	fmt.Println(" load ini: ", global.GWAF_USER_CODE)

	var hosts []model.Hosts

	global.GWAF_LOCAL_DB.Where("user_code = ?", global.GWAF_USER_CODE).Find(&hosts)

	//初始化插件-ip计数器
	pluginIpCounter.InitCounter()

	//初始化步骤[加载ip数据库]
	var dbPath = "data/ip2region.xdb"
	// 1、从 dbPath 加载整个 xdb 到内存
	cBuff, err := xdb.LoadContentFromFile(dbPath)
	if err != nil {
		fmt.Printf("failed to load content from `%s`: %s\n", dbPath, err)
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
		var vcnt int
		global.GWAF_LOCAL_DB.Debug().Model(&model.Rules{}).Where("host_code = ? and user_code=? ",
			hosts[i].Code, global.GWAF_USER_CODE).Select("sum(rule_version) as vcnt").Row().Scan(&vcnt)
		zlog.Debug("主机host" + hosts[i].Code + " 版本" + strconv.Itoa(vcnt))
		var ruleconfigs []model.Rules
		if vcnt > 0 {
			global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and user_code=? ", hosts[i].Code, global.GWAF_USER_CODE).Find(&ruleconfigs)
			ruleHelper.LoadRules(ruleconfigs)
		}

		hostsafe := &HostSafe{
			RevProxy:       nil,
			Rule:           ruleHelper,
			TargetHost:     hosts[i].Remote_host + ":" + strconv.Itoa(hosts[i].Remote_port),
			RuleData:       ruleconfigs,
			RuleVersionSum: vcnt,
			Host:           hosts[i],
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
			log.Println("关闭 recover ", e)
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
