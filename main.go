package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// 主机安全配置
type HostSafe struct {
	RevProxy   *httputil.ReverseProxy
	Rule       utils.RuleHelper
	TargetHost string
	RuleData   model.Rules
}

var (
	//主机情况
	hostTarget = map[string]*HostSafe{}
	//主机和code的关系
	hostCode      = map[string]string{}
	ipcBuff       = []byte{} //ip数据
	server_online = map[int]innerbean.ServerRunTime{}

	//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
	all_certificate = map[int]map[string]*tls.Certificate{}
	//all_certificate = map[int] map[string] string{}
	esHelper utils.EsHelper

	hostRuleChan = make(chan model.Rules, 10) //规则链
	engineChan   = make(chan int, 10)         //引擎链

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
	fs := "HTTP: %d, Code: %d, Message: %s"
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
	len := r.ContentLength

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
	ip_and_port := strings.Split(r.RemoteAddr, ":")
	weblogbean := innerbean.WebLog{
		HOST:           host,
		URL:            r.RequestURI,
		REFERER:        r.Referer(),
		USER_AGENT:     r.UserAgent(),
		METHOD:         r.Method,
		HEADER:         string(header),
		COUNTRY:        GetCountry(ip_and_port[0]),
		SRC_IP:         ip_and_port[0],
		SRC_PORT:       ip_and_port[1],
		CREATE_TIME:    time.Now().Format("2006-01-02 15:04:05"),
		CONTENT_LENGTH: len,
		COOKIES:        string(cookies),
		BODY:           string(bodyByte),
		REQ_UUID:       uuid.NewV4().String(),
		USER_CODE:      global.GWAF_USER_CODE,
	}
	global.GWAF_LOCAL_DB.Create(weblogbean)
	//esHelper.BatchInsert("full_log", weblogbean)
	rule := &innerbean.WAF_REQUEST_FULL{
		SRC_INFO:   weblogbean,
		ExecResult: 0,
	}
	hostTarget[host].Rule.Exec("fact", rule)
	if rule.ExecResult == 1 {

		waflogbean := innerbean.WAFLog{
			CREATE_TIME: time.Now().Format("2006-01-02 15:04:05"),
			RULE:        hostTarget[host].RuleData.Rulename,
			REQ_UUID:    uuid.NewV4().String(),
		}
		esHelper.BatchInsertWAF("web_log", waflogbean)
		log.Println("no china")
		w.Header().Set("WAF", "SAMWAF DROP")
		w.Write([]byte(" no china " + host))
		return
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
			log.Println("target parse fail:", err)
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
			RULE:        hostTarget[host].RuleData.Rulename,
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
		fmt.Printf("Got error  response: %v \n", err)
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

	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("找不到配置文件..")
		} else {
			fmt.Println("配置文件出错..")
		}
	}

	global.GWAF_USER_CODE = config.GetString("user_code") // 读取配置
	global.GWAF_TENANT_ID = global.GWAF_USER_CODE
	global.GWAF_LOCAL_SERVER_PORT = config.GetInt("local_port") //读取本地端口
	fmt.Println(" load ini: ", global.GWAF_USER_CODE)

	//数据库连接
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer（日志输出的目标，前缀和日志包含的内容——译者注）
		logger.Config{
			SlowThreshold:             time.Second,   // 慢 SQL 阈值
			LogLevel:                  logger.Silent, // 日志级别
			IgnoreRecordNotFoundError: true,          // 忽略ErrRecordNotFound（记录未找到）错误
			Colorful:                  false,         // 禁用彩色打印

		},
	)

	//初始化本地数据库
	InitDb()

	dsn := "samwaf:v&GP5e0BRpkm^RA@tcp(bj-cynosdbmysql-grp-37amo1rw.sql.tencentcdb.com:26762)/samwaf?charset=utf8mb4&parseTime=True"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newLogger})
	if err != nil {
		fmt.Printf("error `%s`: %s\n", "db initial error", err)
		return
	}
	var base_config model.Base_config

	db.Debug().Where("name = ?", "esurl").Find(&base_config)
	//esHelper.Init(base_config.Value) todo 暂时屏蔽es

	fmt.Printf("current_version %s \r\n", global.Version_name)

	var hosts []model.Hosts

	db.Where("user_code = ?", global.GWAF_USER_CODE).Find(&hosts)

	//初始化步骤[加载ip数据库]
	var dbPath = "data/ip2region.xdb"
	// 1、从 dbPath 加载整个 xdb 到内存
	cBuff, err := xdb.LoadContentFromFile(dbPath)
	if err != nil {
		fmt.Printf("failed to load content from `%s`: %s\n", dbPath, err)
		return
	}
	ipcBuff = cBuff

	h := &baseHandle{}
	http.Handle("/", h)
	//第一步 检测合法性并加入到全局
	for i := 0; i < len(hosts); i++ {
		//检测https
		if hosts[i].Ssl == 1 {
			//查询ssl证书
			var sslconfig model.Sslconfig
			db.Debug().Where("code = ? and user_code=? ", hosts[i].Code, global.GWAF_USER_CODE).Find(&sslconfig)
			// 第一个域名：example.com
			cert, err := tls.LoadX509KeyPair(sslconfig.Certfile, sslconfig.Keyfile)
			if err != nil {
				log.Fatal("Cannot find %s cert & key file. Error is: %s\n", hosts[i].Host, err)
				continue

			}
			log.Println(cert)
			//all_certificate[hosts[i].Port][hosts[i].Host] = &cert
			mm, ok := all_certificate[hosts[i].Port] //[hosts[i].Host]
			if !ok {
				mm = make(map[string]*tls.Certificate)
				all_certificate[hosts[i].Port] = mm
			}
			all_certificate[hosts[i].Port][hosts[i].Host] = &cert
		}
		_, ok := server_online[hosts[i].Port]
		if ok == false {
			server_online[hosts[i].Port] = innerbean.ServerRunTime{
				ServerType: utils.GetServerByHosts(hosts[i]),
				Port:       hosts[i].Port,
				Status:     0,
			}
		}

		//加载主机对于的规则
		ruleHelper := utils.RuleHelper{}

		//查询规则
		var ruleconfig model.Rules
		db.Debug().Where("code = ? and user_code=? ", hosts[i].Code, global.GWAF_USER_CODE).Find(&ruleconfig)
		ruleHelper.LoadRule(ruleconfig)

		hostsafe := &HostSafe{
			RevProxy:   nil,
			Rule:       ruleHelper,
			TargetHost: hosts[i].Remote_host + ":" + strconv.Itoa(hosts[i].Remote_port),
			RuleData:   ruleconfig,
		}
		//赋值到白名单里面
		hostTarget[hosts[i].Host+":"+strconv.Itoa(hosts[i].Port)] = hostsafe
		//赋值到对照表里面
		hostCode[hosts[i].Code] = hosts[i].Host + ":" + strconv.Itoa(hosts[i].Port)

	}
	for k, v := range server_online {
		go func(port int, innruntime innerbean.ServerRunTime) {

			if (innruntime.ServerType) == "https" {

				svr := &http.Server{
					Addr:    ":" + strconv.Itoa(port),
					Handler: h,
					TLSConfig: &tls.Config{
						NameToCertificate: make(map[string]*tls.Certificate, 0),
					},
				}
				serclone := server_online[k]
				serclone.Svr = svr
				server_online[k] = serclone

				svr.TLSConfig.NameToCertificate = all_certificate[port]
				svr.TLSConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if x509Cert, ok := svr.TLSConfig.NameToCertificate[clientInfo.ServerName]; ok {
						return x509Cert, nil
					}
					return nil, errors.New("config error")
				}

				err = svr.ListenAndServeTLS("", "")
				if err != nil {
					log.Fatal(err)
					return
				}
				println("server final")

			} else {
				defer func() {
					e := recover()
					if e != nil { // 捕获该协程的panic 111111
						fmt.Println("recover ", e)
					}
				}()
				svr := &http.Server{
					Addr:    ":" + strconv.Itoa(port),
					Handler: h,
				}
				serclone := server_online[k]
				serclone.Svr = svr
				server_online[k] = serclone
				println("running2")
				err = svr.ListenAndServe()
				if err == http.ErrServerClosed {
					log.Printf("[HTTPServer] http server has been close, cause:[%v]", err)
				} else {
					log.Fatalf("[HTTPServer] http server start fail, cause:[%v]", err)
				}
				println("server final")

			}

		}(k, v)

	}

	//定时取规则并更新
	go func() {

		for {
			for code, host := range hostCode {
				//hostTarget[host].Rule
				var ruleconfig model.Rules
				db.Debug().Where("code = ? and user_code=? ", code, global.GWAF_USER_CODE).Find(&ruleconfig)
				if ruleconfig.Ruleversion > hostTarget[host].RuleData.Ruleversion {
					//说明该code有更新
					hostRuleChan <- ruleconfig
				}
			}
			time.Sleep(10 * time.Second) // 10s重新读取一次
		}

	}()
}
func main() {

	/*runtime.GOMAXPROCS(1) // 限制 CPU 使用数，避免过载
	runtime.SetMutexProfileFraction(1) // 开启对锁调用的跟踪
	runtime.SetBlockProfileRate(1) // 开启对阻塞操作的跟踪
	go func() {

		err2:=http.ListenAndServe("0.0.0.0:16060", nil)
		time.Sleep(10000)
		log.Fatal(err2)
	}()
	*/
	Start_WAF()
	go func() {
		StartLocalServer()
	}()
	for {
		select {
		case remoteConfig := <-hostRuleChan:
			hostTarget[hostCode[remoteConfig.Code]].RuleData = remoteConfig
			hostTarget[hostCode[remoteConfig.Code]].Rule.LoadRule(remoteConfig)
			log.Println(remoteConfig)
			break
		}
	}
}
