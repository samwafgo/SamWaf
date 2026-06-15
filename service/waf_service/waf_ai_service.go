package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"fmt"

	"gorm.io/gorm"
)

type WafAIService struct{}

var WafAIServiceApp = new(WafAIService)

// DashboardApi 聚合 AI 检测看板数据：按类别汇总、分数分布、observe/block 趋势。
// 数据源为 web_logs 中 ai_score>0 的命中子集（相对较小），按 day 范围/站点过滤。
func (receiver *WafAIService) DashboardApi(req request.WafAIDashboardReq) response2.WafAIDashboard {
	var res response2.WafAIDashboard
	res.Categories = []response2.WafAINameValue{}
	res.Trend = []response2.WafAITrendPoint{}

	if global.GWAF_LOCAL_LOG_DB == nil {
		res.ScoreHist = buildEmptyScoreHist()
		return res
	}

	// 每次查询都用全新的 where 链，避免 GORM 条件被复用污染
	base := func() *gorm.DB {
		q := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where("ai_score > 0")
		if req.StartDay > 0 && req.EndDay > 0 {
			q = q.Where("day between ? and ?", req.StartDay, req.EndDay)
		}
		if req.HostCode != "" {
			q = q.Where("host_code = ?", req.HostCode)
		}
		return q
	}

	// 1) 按类别（rule）汇总
	base().Select("rule as name, count(*) as value").
		Group("rule").Order("value desc").Scan(&res.Categories)

	// 2) 分数分布直方图（10 桶：0.0-0.1 ... 0.9-1.0；score==1.0 归入最后一桶）
	type bucketRow struct {
		Bucket int
		Cnt    int64
	}
	var brows []bucketRow
	base().Select("cast(ai_score*10 as int) as bucket, count(*) as cnt").
		Group("bucket").Scan(&brows)
	counts := make([]int64, 10)
	for _, b := range brows {
		idx := b.Bucket
		if idx >= 10 {
			idx = 9 // score==1.0 归入 0.9-1.0
		}
		if idx < 0 {
			idx = 0
		}
		counts[idx] += b.Cnt
	}
	res.ScoreHist = make([]response2.WafAINameValue, 10)
	for i := 0; i < 10; i++ {
		res.ScoreHist[i] = response2.WafAINameValue{
			Name:  fmt.Sprintf("%.1f-%.1f", float64(i)/10, float64(i+1)/10),
			Value: counts[i],
		}
	}

	// 3) 按天 observe/block 趋势
	base().Select("day, sum(case when log_only_mode=1 then 1 else 0 end) as observe, sum(case when log_only_mode=0 then 1 else 0 end) as block").
		Group("day").Order("day asc").Scan(&res.Trend)

	// 4) 汇总总数
	for _, t := range res.Trend {
		res.ObserveCnt += t.Observe
		res.BlockCnt += t.Block
	}
	res.Total = res.ObserveCnt + res.BlockCnt

	return res
}

func buildEmptyScoreHist() []response2.WafAINameValue {
	hist := make([]response2.WafAINameValue, 10)
	for i := 0; i < 10; i++ {
		hist[i] = response2.WafAINameValue{Name: fmt.Sprintf("%.1f-%.1f", float64(i)/10, float64(i+1)/10)}
	}
	return hist
}
