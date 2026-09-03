package wafbot

import (
	"SamWaf/global"
	"context"
	"net"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// dnsGroup 合并同一时刻对同一个 key 的重复查询。
//
// 一个新爬虫 IP 突然打进来几十个并发请求时，缓存里还没有结果，
// 没有它就会几十个请求各发一次 DNS，查的还是同一个 IP，
// 等第一个结果写进缓存，其余的查询已经白发了。
var dnsGroup singleflight.Group

func dnsResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", global.GWAF_RUNTIME_DNS_SERVER+":53")
		},
	}
}

func dnsTimeout() time.Duration {
	return time.Duration(global.GWAF_RUNTIME_DNS_TIMEOUT) * time.Millisecond
}

// ReverseDNSLookup 反查 IP 的 PTR 记录
func ReverseDNSLookup(ipAddress string) ([]string, error) {
	v, err, _ := dnsGroup.Do("r:"+ipAddress, func() (interface{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout())
		defer cancel()
		return dnsResolver().LookupAddr(ctx, ipAddress)
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

// ForwardDNSLookup 正向解析域名
func ForwardDNSLookup(name string) ([]string, error) {
	v, err, _ := dnsGroup.Do("f:"+name, func() (interface{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout())
		defer cancel()
		return dnsResolver().LookupHost(ctx, name)
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

// ForwardConfirms 判断域名是否能正向解析回给定的 IP。
//
// 这是 Google / 百度等官方文档要求的验证闭环：反向拿到域名之后，
// 再正向解析该域名，确认结果里包含最初那个来访 IP。
// 返回 confirmed=false 时不代表一定是伪装——也可能是这个域名压根没有正向记录
// （实测百度 180.76.x 老抓取段就是这种情况），调用方需要自己决定怎么对待。
func ForwardConfirms(name, ip string) bool {
	if name == "" || ip == "" {
		return false
	}
	addrs, err := ForwardDNSLookup(name)
	if err != nil {
		return false
	}
	target := net.ParseIP(ip)
	for _, a := range addrs {
		if a == ip {
			return true
		}
		// 同一个地址的文本写法可能不同（IPv6 尤其），按地址值再比一次
		if target != nil && net.ParseIP(a) != nil && net.ParseIP(a).Equal(target) {
			return true
		}
	}
	return false
}

// matchAnySuffix 判断 PTR 域名是否落在某家爬虫的域名后缀里
func matchAnySuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
