package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
)

type WafAnalysisService struct{}

var WafAnalysisServiceApp = new(WafAnalysisService)

// StatAnalysisDayCountryRangeApi 通过时间获取国家级别的 攻击数 访问数
func (receiver *WafAnalysisService) StatAnalysisDayCountryRangeApi(req request.WafStatsAnalysisDayRangeCountryReq) []response2.WafAnalysisDayStats {
	var CountOfRange []response2.WafAnalysisDayStats
	if req.AttackType == "" {
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPCityDay{}).Where("day between ? and ? and country<>? and country<>? ",
			req.StartDay, req.EndDay, "0", "内网").Select(" country as Name ,sum(count) as Value").Group("country").Order("sum(count) desc").Scan(&CountOfRange)

	} else {
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPCityDay{}).Where("day between ? and ? and type = ?  and country<>? and country<>? ",
			req.StartDay, req.EndDay, req.AttackType, "0", "内网").Select(" country as Name ,sum(count) as Value").Group("country").Order("sum(count) desc").Scan(&CountOfRange)

	}
	return CountOfRange
}

// AnalysisSpiderApi 爬虫分析
func (receiver *WafAnalysisService) AnalysisSpiderApi(req request.WafAnalysisSpiderReq) []response2.WafAnalysisSpiderResp {
	var CountOfRange []response2.WafAnalysisSpiderResp
	if req.Host == "" {
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where("day between ? and ? and  is_bot=1 ",
			req.StartDay, req.EndDay).Select(" guest_id_entification as Name ,count(1) as Value").
			Group("guest_id_entification").Order("count(1) desc").Scan(&CountOfRange)

	} else {
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where("day between ? and ? and  is_bot=1 and host_code = ? ",
			req.StartDay, req.EndDay, req.Host).
			Select(" guest_id_entification as Name ,count(1) as Value").
			Group("guest_id_entification").Order("count(1) desc").Scan(&CountOfRange)
	}
	return CountOfRange
}
