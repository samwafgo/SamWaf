package main

import (
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	// 建立域名和目标map
	hostTarget = map[string]string{
		"mybaidu1.com:8082": "http://dhjemu.binaite.net",
		"mybing2.com:8082":  "http://djdemu.binaite.net",
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

	server := &http.Server{
		Addr:    ":8082",
		Handler: h,
	}
	log.Fatal(server.ListenAndServe())
	// 备注：并发使用，每个 goroutine 需要创建一个独立的 searcher 对象。
}
