package wafbot

import (
	"SamWaf/utils"
	"strings"
)

// BotResult 检测结果
type BotResult struct {
	IsBot       bool   //是否是爬虫
	IsNormalBot bool   //是否是正常爬虫 false 会拦截
	BotName     string //爬虫名称
}

/*
*
判断是否正确的搜索引擎 返回值： 是否是爬虫，是否是正常爬虫， 爬虫名称
*/
func DetermineNormalSearch(userAgent, ip string) BotResult {
	if strings.Contains(userAgent, "Baiduspider") {
		return baiduSpider(ip)
	} else if strings.Contains(userAgent, "google") {
		return googleSpider(ip)
	} else if strings.Contains(userAgent, "bingbot") || strings.Contains(userAgent, "msn.com") {
		return bingSpider(ip)
	} else if strings.Contains(userAgent, "sogou") {
		return sogouSpider(ip)
	} else if strings.Contains(userAgent, "360Spider") {
		return spider360(ip)
	} else if strings.Contains(userAgent, "YisouSpider") {
		return yisouSpider(ip)
	} else if strings.Contains(userAgent, "Bytespider") {
		return byteSpider(ip)
	}
	return BotResult{false, false, ""}
}

/*
*
百度的蜘蛛
*/
func baiduSpider(ip string) BotResult {
	//先查询本地库
	//然后远端查询
	lookup, err := ReverseDNSLookup(ip)
	if err == nil {
		if len(lookup) > 0 {
			if strings.HasSuffix(lookup[0], ".baidu.com.") || strings.HasSuffix(lookup[0], ".baidu.jp.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "百度爬虫",
				}
			} else {
				return BotResult{
					IsBot:       true,
					IsNormalBot: false,
					BotName:     "可能不是百度爬虫",
				}
			}
		} else {
			return BotResult{
				IsBot:       true,
				IsNormalBot: false,
				BotName:     "可能不是百度爬虫",
			}
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "查询超时",
		}
	}
}

/*
*
谷歌的蜘蛛
*/
func googleSpider(ip string) BotResult {
	//先查询本地库
	//然后远端查询
	lookup, err := ReverseDNSLookup(ip)
	if err == nil {
		if len(lookup) > 0 {
			if strings.HasSuffix(lookup[0], ".googlebot.com.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "Google爬虫",
				}
			} else if strings.HasSuffix(lookup[0], ".google.com.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "Google爬虫(特殊)",
				}
			} else if strings.HasSuffix(lookup[0], ".googleusercontent.com.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "Google爬虫(用户触发)",
				}
			} else {
				return BotResult{
					IsBot:       true,
					IsNormalBot: false,
					BotName:     "可能不是Google爬虫",
				}
			}
		} else {
			return BotResult{
				IsBot:       true,
				IsNormalBot: false,
				BotName:     "可能不是Google爬虫",
			}
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "查询超时",
		}
	}
}

/*
*
bing的蜘蛛
*/
func bingSpider(ip string) BotResult {
	//先查询本地库
	//然后远端查询
	lookup, err := ReverseDNSLookup(ip)
	if err == nil {
		if len(lookup) > 0 {
			if strings.HasSuffix(lookup[0], ".msn.com.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "Bing爬虫",
				}
			} else {
				return BotResult{
					IsBot:       true,
					IsNormalBot: false,
					BotName:     "可能不是Bing爬虫",
				}
			}
		} else {
			return BotResult{
				IsBot:       true,
				IsNormalBot: false,
				BotName:     "可能不是Bing爬虫",
			}
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "可能不是Bing爬虫",
		}
	}
}

/*
*
sogou蜘蛛
*/
func sogouSpider(ip string) BotResult {
	//先查询本地库
	//然后远端查询
	lookup, err := ReverseDNSLookup(ip)
	if err == nil {
		if len(lookup) > 0 {
			if strings.HasSuffix(lookup[0], ".sogou.com.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "搜狗爬虫",
				}
			} else {
				return BotResult{
					IsBot:       true,
					IsNormalBot: false,
					BotName:     "可能不是搜狗爬虫",
				}
			}
		} else {
			return BotResult{
				IsBot:       true,
				IsNormalBot: false,
				BotName:     "可能不是搜狗爬虫",
			}
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "查询超时",
		}
	}
}

/*
*
360 搜索引擎
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
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "360爬虫",
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: false,
			BotName:     "伪装360爬虫",
		}
	}
}

/*
*
UC 搜索
*/
func yisouSpider(ip string) BotResult {
	//先查询本地库
	//然后远端查询
	lookup, err := ReverseDNSLookup(ip)
	if err == nil {
		if len(lookup) > 0 {
			if strings.HasSuffix(lookup[0], ".sm.cn.") {
				return BotResult{
					IsBot:       true,
					IsNormalBot: true,
					BotName:     "神马搜索爬虫",
				}
			} else {
				return BotResult{
					IsBot:       true,
					IsNormalBot: false,
					BotName:     "可能不是神马搜索爬虫",
				}
			}
		} else {
			return BotResult{
				IsBot:       true,
				IsNormalBot: false,
				BotName:     "可能不是神马搜索爬虫",
			}
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "查询超时",
		}
	}
}

/*
*
字节跳动的爬虫
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

	isInRanges := utils.CheckIPInRanges(ip, ipRanges)
	if isInRanges {
		return BotResult{
			IsBot:       true,
			IsNormalBot: true,
			BotName:     "字节跳动爬虫",
		}
	} else {
		return BotResult{
			IsBot:       true,
			IsNormalBot: false,
			BotName:     "伪装字节跳动爬虫",
		}
	}
}
