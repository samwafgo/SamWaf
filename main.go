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
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
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
}

var (
	// 建立域名和目标map
	/*hostTarget = map[string]string{
		//"mybaidu1.com:8082": "http://dhjemu.binaite.net",
		//"mybing2.com:8082":  "http://djdemu.binaite.net",
	}*/
	// 用于缓存 httputil.ReverseProxy
	/*hostProxy     = map[string]*httputil.ReverseProxy{}*/

	hostTarget    = map[string]*HostSafe{}
	ipcBuff       = []byte{} //ip数据
	server_online = map[int]innerbean.ServerRunTime{}

	//所有证书情况 对应端口 可能多个端口都是https 443，或者其他非标准端口也要实现https证书
	all_certificate = map[int]map[string]*tls.Certificate{}
	//all_certificate = map[int] map[string] string{}
	esHelper utils.EsHelper
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
	// 获取请求报文的内容长度
	len := r.ContentLength

	var bodyByte []byte

	// 拷贝一份request的Body
	if r.Body != nil {
		bodyByte, _ = io.ReadAll(r.Body)
		// 把刚刚读出来的再写进去，不然后面解析表单数据就解析不到了
		r.Body = io.NopCloser(bytes.NewBuffer(bodyByte))
	}
	log.Println(string(bodyByte))

	cookies, _ := json.Marshal(r.Cookies())
	log.Println(string(cookies))

	log.Println(r.Header)
	header, _ := json.Marshal(r.Header)
	log.Println(r.Proto)
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
	}
	esHelper.BatchInsert(weblogbean)
	rule := &innerbean.WAF_REQUEST_FULL{
		SRC_INFO:   weblogbean,
		ExecResult: 0,
	}
	hostTarget[host].Rule.Exec("fact", rule)
	if rule.ExecResult == 1 {
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
	}
	w.Write([]byte("403: Host forbidden " + host))
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
func main() {

	/*rule := &innerbean.WAF_REQUEST_FULL{
		SRC_INFO: innerbean.WebLog{
			HOST:           "cc9",
			URL:            "",
			REFERER:        "",
			USER_AGENT:     "",
			METHOD:         "",
			HEADER:         "",
			SRC_IP:         "",
			SRC_PORT:       "",
			COUNTRY:        "",
			CREATE_TIME:    "",
			CONTENT_LENGTH: 0,
			COOKIES:        "",
			BODY:           "",
		},
		ExecResult: 0,
	}
	ruleerr := ruleHelper.Exec("fact", rule)
	if ruleerr != nil {
		log.Fatal(ruleerr)
	}*/

	esHelper.Init()

	fmt.Printf("current_version %s \r\n", global.Version_name)

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

	dsn := "samwaf:v&GP5e0BRpkm^RA@tcp(bj-cynosdbmysql-grp-37amo1rw.sql.tencentcdb.com:26762)/samwaf?charset=utf8mb4&parseTime=True"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: newLogger})
	if err != nil {
		fmt.Printf("error `%s`: %s\n", "db initial error", err)
		return
	}
	var hosts []model.Hosts

	db.Find(&hosts)

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
			db.Debug().Where("code = ?", hosts[i].Code).Find(&sslconfig)
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
		ruleHelper.LoadRule("")

		hostsafe := &HostSafe{
			RevProxy:   nil,
			Rule:       ruleHelper,
			TargetHost: hosts[i].Remote_host + ":" + strconv.Itoa(hosts[i].Remote_port),
		}
		//赋值到白名单里面
		hostTarget[hosts[i].Host+":"+strconv.Itoa(hosts[i].Port)] = hostsafe

	}
	for k, v := range server_online {
		go func(port int, innruntime innerbean.ServerRunTime) {

			if (innruntime.ServerType) == "https" {

				srv := &http.Server{
					Addr:    ":" + strconv.Itoa(port),
					Handler: h,
					TLSConfig: &tls.Config{
						NameToCertificate: make(map[string]*tls.Certificate, 0),
					},
				}
				srv.TLSConfig.NameToCertificate = all_certificate[port]
				srv.TLSConfig.GetCertificate = func(clientInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if x509Cert, ok := srv.TLSConfig.NameToCertificate[clientInfo.ServerName]; ok {
						return x509Cert, nil
					}
					return nil, errors.New("config error")
				}

				err = srv.ListenAndServeTLS("", "")

			} else {
				server := &http.Server{
					Addr:    ":" + strconv.Itoa(port),
					Handler: h,
				}
				err = server.ListenAndServe()
			}
			log.Fatal(err)

		}(k, v)

	}
	var name string

	fmt.Scanln(&name) //此处&变量名是地址
}
