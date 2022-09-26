package main

import (
	"SamWaf/global"
	"SamWaf/model"
	"crypto/tls"
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	// 建立域名和目标map
	hostTarget = map[string]string{
		//"mybaidu1.com:8082": "http://dhjemu.binaite.net",
		//"mybing2.com:8082":  "http://djdemu.binaite.net",
	}
	// 用于缓存 httputil.ReverseProxy
	hostProxy = map[string]*httputil.ReverseProxy{}
	ipcBuff   = []byte{} //ip数据
)

type baseHandle struct{}

func CheckIP(ip string) bool {
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
		return true
	}

	fmt.Printf("{region: %s, took: %s}\n", region, time.Since(tStart))
	regions := strings.Split(region, "|")
	println(regions[0])
	if regions[0] == "中国" {
		return true
	} else if regions[0] == "0" {
		return true
	} else {
		return false
	}
}

func (h *baseHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// 取出客户IP
	ip_and_port := strings.Split(r.RemoteAddr, ":")
	println(ip_and_port[0])
	if !CheckIP(ip_and_port[0]) {
		log.Println("no china")
		w.Write([]byte(" no china " + host))
		return
	}
	// 取出代理ip

	// 直接从缓存取出
	if fn, ok := hostProxy[host]; ok {
		fn.ServeHTTP(w, r)
		return
	}

	// 检查域名白名单
	if target, ok := hostTarget[host]; ok {
		remoteUrl, err := url.Parse(target)
		if err != nil {
			log.Println("target parse fail:", err)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(remoteUrl)
		hostProxy[host] = proxy // 放入缓存
		proxy.ServeHTTP(w, r)
		return
	}
	w.Write([]byte("403: Host forbidden " + host))
}
func main() {

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
	for i := 0; i < len(hosts); i++ {
		hostTarget[hosts[i].Host+":"+strconv.Itoa(hosts[i].Port)] = hosts[i].Remote_host + ":" + strconv.Itoa(hosts[i].Remote_port)
		go func(host model.Hosts) {
			fmt.Printf("init " + host.Host)
			if (host.Ssl) == 1 {
				//查询ssl证书
				var sslconfig model.Sslconfig
				db.Debug().Where("code = ?", host.Code).Find(&sslconfig)
				server := &http.Server{
					Addr:    ":" + strconv.Itoa(host.Port),
					Handler: h,
					TLSConfig: &tls.Config{
						MinVersion:               tls.VersionTLS13,
						PreferServerCipherSuites: true,
					},
				}
				err = server.ListenAndServeTLS(sslconfig.Certfile, sslconfig.Keyfile)

			} else {
				server := &http.Server{
					Addr:    ":" + strconv.Itoa(host.Port),
					Handler: h,
				}
				err = server.ListenAndServe()
			}
			log.Fatal(err)

		}(hosts[i])

	}
	var name string

	fmt.Scanln(&name) //此处&变量名是地址
}
