// Package clientip 提供业务侧"真实客户端 IP 提取加固"所需的 CDN 厂商注册表与回源 IP 段缓存。
// 放在叶子包，供 wafenginecore(判定读) 与 service(拉取写) 共同引用，避免 import cycle。
package clientip

import (
	"SamWaf/wafenginecore/ipset"
	"sync"
)

// Tier 厂商档位：A=官方公开回源段可匿名自动拉取并严格校验来源；A'=需凭证认证 API；B=无公开段，仅信任 header/手填。
const (
	TierA    = "A"      // 匿名自动拉取 + 严格来源校验
	TierAuth = "A_auth" // 需凭证认证 API(EdgeOne)
	TierB    = "B"      // 无公开段，仅 header 信任/手填
)

// FetchKind 回源段拉取方式
const (
	FetchNone       = "none"         // 不自动拉取(Tier B / 手填)
	FetchPlain      = "anon_plain"   // 匿名纯文本一行一段(可多 URL，如 Cloudflare v4/v6)
	FetchFastlyJSON = "anon_fastly"  // Fastly public-ip-list JSON
	FetchAWSJSON    = "anon_aws"     // AWS ip-ranges.json(过滤 CLOUDFRONT_ORIGIN_FACING)
	FetchTencent    = "auth_tencent" // 腾讯云 DescribeOriginACL(需凭证)
	FetchAliyun     = "auth_aliyun"  // 阿里云 DescribeCdnIpInfo/回源段(需凭证)
)

// Provider CDN 厂商元数据
type Provider struct {
	Code      string   // 厂商码
	Name      string   // 显示名
	Header    string   // 真实客户端 IP 头
	Tier      string   // 档位
	FetchKind string   // 拉取方式
	RangeURLs []string // 回源段拉取地址(可多个)
}

// Providers CDN 厂商注册表。Tier A 可匿名自动拉取回源段做严格来源校验；Tier B 仅信任 header 或用户手填网段。
var Providers = map[string]Provider{
	"cloudflare": {
		Code: "cloudflare", Name: "Cloudflare", Header: "CF-Connecting-IP", Tier: TierA, FetchKind: FetchPlain,
		RangeURLs: []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"},
	},
	"fastly": {
		Code: "fastly", Name: "Fastly", Header: "Fastly-Client-IP", Tier: TierA, FetchKind: FetchFastlyJSON,
		RangeURLs: []string{"https://api.fastly.com/public-ip-list"},
	},
	"cloudfront": {
		Code: "cloudfront", Name: "AWS CloudFront", Header: "CloudFront-Viewer-Address", Tier: TierA, FetchKind: FetchAWSJSON,
		RangeURLs: []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
	},
	"edgeone": {
		// 旧匿名端点 api.edgeone.ai/ips 已下线；自动同步走腾讯云 DescribeOriginACL(需凭证)。
		Code: "edgeone", Name: "腾讯云 EdgeOne", Header: "EO-Client-IP", Tier: TierAuth, FetchKind: FetchTencent,
	},
	"aliyun": {
		// 阿里云回源段走认证 API DescribeCdnIpInfo/回源IP(需 AccessKey)。
		Code: "aliyun", Name: "阿里云 CDN/DCDN", Header: "Ali-Cdn-Real-Ip", Tier: TierAuth, FetchKind: FetchAliyun,
	},
	"akamai": {
		Code: "akamai", Name: "Akamai", Header: "True-Client-IP", Tier: TierB, FetchKind: FetchNone,
	},
}

// providerMatchers 各厂商回源段编译后的 MatchSet 缓存(code -> *ipset.MatchSet)
var providerMatchers sync.Map

// SetProviderRanges 发布某厂商的回源段匹配集(由 service 拉取后调用)
func SetProviderRanges(code string, m *ipset.MatchSet) {
	providerMatchers.Store(code, m)
}

// GetProviderRanges 读取某厂商回源段匹配集(可能为 nil)
func GetProviderRanges(code string) *ipset.MatchSet {
	if v, ok := providerMatchers.Load(code); ok {
		return v.(*ipset.MatchSet)
	}
	return nil
}

// IsProviderIP 判断某 IP 是否属于该厂商已缓存的回源段
func IsProviderIP(code, ip string) bool {
	m := GetProviderRanges(code)
	return m.ContainsStr(ip)
}

// DefaultHeader 返回厂商默认真实 IP 头(未知厂商返回空)
func DefaultHeader(code string) string {
	if p, ok := Providers[code]; ok {
		return p.Header
	}
	return ""
}
