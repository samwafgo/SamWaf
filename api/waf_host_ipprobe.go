package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/wafenginecore"
	"strings"

	"github.com/gin-gonic/gin"
)

// ipProbeSampleView 一条采样 + 按当前配置算出的判定结论
type ipProbeSampleView struct {
	wafenginecore.IPProbeSample
	NetIPTrusted        bool   `json:"net_ip_trusted"`        //网络层上一跳是否通过可信来源校验
	ConfigHeaderPresent bool   `json:"config_header_present"` //当前配置的真实IP头这次请求里有没有
	ConfigHeaderIP      string `json:"config_header_ip"`      //该头里第一个合法IP
}

// ipProbeResp 真实IP来源诊断返回
type ipProbeResp struct {
	HostCode           string              `json:"host_code"`
	IPMode             string              `json:"ip_mode"`              //nic / proxy
	IPSourceMode       string              `json:"ip_source_mode"`       //""(兼容) / nic / header / xff_depth / cdn_preset
	CDNProvider        string              `json:"cdn_provider"`         //cdn_preset 选择的厂商
	EffectiveHeader    string              `json:"effective_header"`     //当前模式实际生效的头名(兼容模式为全局配置头)
	TrustProxies       string              `json:"ip_trust_proxies"`     //可信代理网段(原样回显，本就是用户自己填的)
	ProviderRangeCount int                 `json:"provider_range_count"` //厂商回源段条数(cdn_preset)
	CompatHeaderUnset  bool                `json:"compat_header_unset"`  //兼容模式但全局「获取访客IP头信息」为空(此时永远只能取到网络层IP)
	SampleIntervalSec  int                 `json:"sample_interval_sec"`  //采样最小间隔，界面提示用
	ProbeEnabled       bool                `json:"probe_enabled"`        //探针开关(系统配置 ipprobe_enable)，关闭时不会有任何采样
	MaxSamples         int                 `json:"max_samples"`          //每站保留的样本条数上限
	Samples            []ipProbeSampleView `json:"samples"`
}

// IPSourceProbeApi 查看某站点最近到达的真实请求头(已脱敏)，用于排查"真实IP来源"配置。
// 数据来自引擎内存里的环形采样，不落库、不依赖访问日志开关。
func (w *WafHostAPi) IPSourceProbeApi(c *gin.Context) {
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		response.FailWithMessage("参数错误", c)
		return
	}
	host := wafHostService.GetDetailByCodeApi(code)
	if host.Code == "" {
		response.FailWithMessage("网站不存在", c)
		return
	}

	effectiveHeader := wafenginecore.IPSourceEffectiveHeader(host)
	if host.IPSourceMode == "" {
		// 兼容模式取全局「获取IP头信息」配置，可能配了多个，原样展示第一个之外的也一并给出
		effectiveHeader = strings.TrimSpace(global.GCONFIG_RECORD_PROXY_HEADER)
	}

	samples := wafenginecore.GetIPProbeSamples(code)
	views := make([]ipProbeSampleView, 0, len(samples))
	for _, sample := range samples {
		view := ipProbeSampleView{
			IPProbeSample: sample,
			NetIPTrusted:  wafenginecore.IsIPSourceTrustedPeer(host, sample.NetIP),
		}
		for _, header := range sample.Headers {
			if headerNameMatched(header.Name, effectiveHeader) {
				view.ConfigHeaderPresent = true
				view.ConfigHeaderIP = header.ParsedIP
				break
			}
		}
		views = append(views, view)
	}

	response.OkWithDetailed(ipProbeResp{
		HostCode:           host.Code,
		IPMode:             host.IPMode,
		IPSourceMode:       host.IPSourceMode,
		CDNProvider:        host.CDNProvider,
		EffectiveHeader:    effectiveHeader,
		TrustProxies:       host.IPTrustProxies,
		ProviderRangeCount: wafenginecore.IPSourceProviderRangeCount(host),
		CompatHeaderUnset:  host.IPSourceMode == "" && effectiveHeader == "",
		SampleIntervalSec:  1,
		ProbeEnabled:       wafenginecore.IPProbeEnabled(),
		MaxSamples:         wafenginecore.IPProbeMaxSamples(),
		Samples:            views,
	}, "获取成功", c)
}

// IPSourceProbeClearApi 清空某站点的采样，方便"改完配置再访问一次"对比
func (w *WafHostAPi) IPSourceProbeClearApi(c *gin.Context) {
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		response.FailWithMessage("参数错误", c)
		return
	}
	wafenginecore.ClearIPProbeSamples(code)
	response.OkWithMessage("清空成功", c)
}

// headerNameMatched 头名不区分大小写比较；兼容模式下全局配置可能是逗号分隔的多个头
func headerNameMatched(name, configured string) bool {
	if strings.TrimSpace(configured) == "" {
		return false
	}
	for _, item := range strings.Split(configured, ",") {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}
