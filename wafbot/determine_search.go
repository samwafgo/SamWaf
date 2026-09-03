package wafbot

import (
	"SamWaf/utils"
	"errors"
	"net"
	"strings"
)

// BotResult 检测结果
type BotResult struct {
	IsBot       bool   //是否是爬虫
	IsNormalBot bool   //是否是正常爬虫 false 会拦截
	BotName     string //爬虫名称

	// StrongVerified 表示身份验证走完了完整闭环：
	//   - DNS 类：反向拿到域名 → 后缀匹配 → 正向解析该域名 → 结果包含原 IP
	//   - IP 段类：来访 IP 落在厂商公布的网段内
	// 只有反向匹配、正向没能确认时它为 false——这时仍按原来的判定放行（不判伪装），
	// 但需要更强把握的场合（如 CC 豁免）不应采信。
	StrongVerified bool
}

// dnsSpider 一家用 DNS 验证身份的爬虫
type dnsSpider struct {
	fakeName string //反向解析对不上时的名称
	rules    []suffixRule
}

type suffixRule struct {
	suffix  string
	botName string
}

var (
	baiduRules = dnsSpider{
		fakeName: "伪装百度爬虫",
		rules: []suffixRule{
			{".baidu.com.", "百度爬虫"},
			{".baidu.jp.", "百度爬虫"},
		},
	}
	googleRules = dnsSpider{
		fakeName: "伪装Google爬虫",
		rules: []suffixRule{
			{".googlebot.com.", "Google爬虫"},
			{".google.com.", "Google爬虫(特殊)"},
			{".googleusercontent.com.", "Google爬虫(用户触发)"},
		},
	}
	bingRules = dnsSpider{
		fakeName: "伪装Bing爬虫",
		rules:    []suffixRule{{".msn.com.", "Bing爬虫"}},
	}
	sogouRules = dnsSpider{
		fakeName: "伪装搜狗爬虫",
		rules:    []suffixRule{{".sogou.com.", "搜狗爬虫"}},
	}
	yisouRules = dnsSpider{
		fakeName: "伪装神马搜索爬虫",
		rules:    []suffixRule{{".sm.cn.", "神马搜索爬虫"}},
	}
)

/*
*
判断是否正确的搜索引擎 返回值： 是否是爬虫，是否是正常爬虫， 爬虫名称
*/
func DetermineNormalSearch(userAgent, ip string) BotResult {
	if strings.Contains(userAgent, "Baiduspider") {
		return verifyByDNS(ip, baiduRules)
	} else if strings.Contains(userAgent, "google") {
		return verifyByDNS(ip, googleRules)
	} else if strings.Contains(userAgent, "bingbot") || strings.Contains(userAgent, "msn.com") {
		return verifyByDNS(ip, bingRules)
	} else if strings.Contains(userAgent, "sogou") {
		return verifyByDNS(ip, sogouRules)
	} else if strings.Contains(userAgent, "360Spider") {
		return spider360(ip)
	} else if strings.Contains(userAgent, "YisouSpider") {
		return verifyByDNS(ip, yisouRules)
	} else if strings.Contains(userAgent, "Bytespider") {
		return byteSpider(ip)
	}
	return BotResult{false, false, "", false}
}

// verifyByDNS 用「正向确认的反向 DNS」验证爬虫身份。
//
// 步骤按各家官方文档：反向拿 PTR → 域名后缀匹配 → 正向解析该域名 → 确认能解析回原 IP。
//
// 正向确认失败时**不判伪装**，只是不给 StrongVerified。原因有二：
//   - 实测百度 180.76.x 老抓取段的 PTR 域名没有正向记录，严格执行会把真 Baiduspider 判成伪装，
//     而伪装爬虫在开启拦截时是直接挡下的，后果是掉索引
//   - 正向查询本身会超时（实测冷启动可达 500ms 上限），DNS 抖一下就封搜索引擎，代价太大
//
// 需要更强把握的场合改为只认 StrongVerified，这样既不放松拦截、也不误伤。
func verifyByDNS(ip string, spider dnsSpider) BotResult {
	fake := BotResult{IsBot: true, IsNormalBot: false, BotName: spider.fakeName}

	lookup, err := ReverseDNSLookup(ip)
	if err != nil {
		return dnsErrResult(err, fake)
	}
	if len(lookup) == 0 {
		return fake
	}
	name := lookup[0]
	for _, rule := range spider.rules {
		if !strings.HasSuffix(name, rule.suffix) {
			continue
		}
		return BotResult{
			IsBot:          true,
			IsNormalBot:    true,
			BotName:        rule.botName,
			StrongVerified: ForwardConfirms(name, ip),
		}
	}
	return fake
}

// dnsErrResult 反向查询本身出错时的口径，沿用既有行为：
// 超时与其它错误按「存疑放行」处理，只有明确的 NXDOMAIN 才判伪装。
func dnsErrResult(err error, fake BotResult) BotResult {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return BotResult{IsBot: true, IsNormalBot: true, BotName: "查询超时"}
		}
		if dnsErr.IsNotFound {
			return fake
		}
	}
	return BotResult{IsBot: true, IsNormalBot: true, BotName: "查询失败"}
}

/*
*
360搜索：按厂商公布的网段验证，不查 DNS
*/
func spider360(ip string) BotResult {
	// 将要检查的 IP 地址段转换成数组
	ipRanges := []string{
		"180.153.232.",
		"180.153.234.",
		"180.153.236.",
		"180.163.220.",
		"42.236.101.",
		"42.236.102.",
		"42.236.103.",
		"42.236.10.",
		"42.236.12.",
		"42.236.13.",
		"42.236.14.",
		"42.236.15.",
		"42.236.16.",
		"42.236.17.",
		"42.236.46.",
		"42.236.48.",
		"42.236.49.",
		"42.236.50.",
		"42.236.51.",
		"42.236.52.",
		"42.236.53.",
		"42.236.54.",
		"42.236.55.",
		"42.236.99.",
	}
	// 判断指定 IP 是否在数组中的 IP 地址段范围内
	isInRange := false
	for _, ipRange := range ipRanges {
		if strings.HasPrefix(ip, ipRange) {
			isInRange = true
			break
		}
	}
	if isInRange {
		// 落在公布网段内即为完整验证：这条路径不依赖 DNS，没有"确认不了"的中间态
		return BotResult{
			IsBot:          true,
			IsNormalBot:    true,
			BotName:        "360爬虫",
			StrongVerified: true,
		}
	}
	return BotResult{
		IsBot:       true,
		IsNormalBot: false,
		BotName:     "伪装360爬虫",
	}
}

/*
*
字节跳动：按厂商公布的网段验证，不查 DNS
*/
func byteSpider(ip string) BotResult {
	ipRanges := []string{
		"110.249.201.0/24",
		"110.249.202.0/24",
		"111.225.148.0/24",
		"111.225.149.0/24",
		"220.243.135.0/24",
		"220.243.136.0/24",
		"220.243.188.0/24",
		"220.243.189.0/24",
		"60.8.123.0/24",
		"60.8.151.0/24",
	}

	if utils.CheckIPInRanges(ip, ipRanges) {
		return BotResult{
			IsBot:          true,
			IsNormalBot:    true,
			BotName:        "字节跳动爬虫",
			StrongVerified: true,
		}
	}
	return BotResult{
		IsBot:       true,
		IsNormalBot: false,
		BotName:     "伪装字节跳动爬虫",
	}
}
