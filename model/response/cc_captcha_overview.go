package response

// CCCaptchaSiteRep 一个站点的人机验证要点。
type CCCaptchaSiteRep struct {
	HostCode    string `json:"host_code"`
	HostName    string `json:"host_name"`
	EngineType  string `json:"engine_type"`
	ExcludeURLs string `json:"exclude_urls"`
}

// CCCaptchaOverviewRep 各站点的人机验证要点汇总。
//
// 全局 CC 规则对所有站点生效，而人机验证的能力与「永不挑战的路径」是各站点各自的配置，
// 引擎发起挑战时取的是被命中的那个真实站点的配置。所以全局规则要看的不是某一个站点，
// 而是这份逐站点清单。Sites 只收「配了永不挑战的路径」的站点——没配的站点不影响判断，
// 全列出来只会把真正要看的那几条淹掉。
type CCCaptchaOverviewRep struct {
	HostTotal int                `json:"host_total"`
	Sites     []CCCaptchaSiteRep `json:"sites"`
}
