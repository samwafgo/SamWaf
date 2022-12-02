package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"strconv"
	"time"
)

type WafStatService struct{}

var WafStatServiceApp = new(WafStatService)

func (receiver *WafStatService) StatHomeSumDayApi() (response2.WafStat, error) {
	currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))
	yesterdayDay, _ := strconv.Atoi(time.Now().AddDate(0, 0, -1).Format("20060102"))

	var AttackCountOfToday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Select("sum(count) as vcnt").Row().Scan(&AttackCountOfToday)

	var VisitCountOfToday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day = ? ",
		currentDay).Select("sum(count) as vcnt").Row().Scan(&VisitCountOfToday)

	var AttackCountOfYesterday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		yesterdayDay, "阻止").Select("sum(count) as vcnt").Row().Scan(&AttackCountOfYesterday)

	var VisitCountOfYesterday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day = ? ",
		yesterdayDay).Select("sum(count) as vcnt").Row().Scan(&VisitCountOfYesterday)

	var NormalIpCountOfToday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "放行").Group("ip").Count(&NormalIpCountOfToday)

	var IllegalIpCountOfToday int64
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Group("ip").Count(&IllegalIpCountOfToday)
	return response2.WafStat{
			AttackCountOfToday:          AttackCountOfToday,
			VisitCountOfToday:           VisitCountOfToday,
			AttackCountOfYesterday:      AttackCountOfYesterday,
			VisitCountOfYesterday:       VisitCountOfYesterday,
			AttackCountOfLastWeekToday:  0,
			VisitCountOfLastWeekToday:   0,
			NormalIpCountOfToday:        NormalIpCountOfToday,
			IllegalIpCountOfToday:       IllegalIpCountOfToday,
			NormalCountryCountOfToday:   0,
			IllegalCountryCountOfToday:  0,
			NormalProvinceCountOfToday:  0,
			IllegalProvinceCountOfToday: 0,
			NormalCityCountOfToday:      0,
			IllegalCityCountOfToday:     0,
		},
		nil
}

func (receiver *WafStatService) StatHomeSumDayRangeApi(req request.WafStatsDayRangeReq) (response2.WafStatRange, error) {
	var rangeAttackMap = map[int]int64{}
	var rangeNormalMap = map[int]int64{}
	var rangeInt = (int)(utils.Str2Time(req.EndDay).Sub(utils.Str2Time(req.StartDay)).Hours() / 24)

	for i := 0; i < rangeInt; i++ {
		rangeAttackMap[utils.TimeToDayInt(utils.Str2Time(req.StartDay).AddDate(0, 0, i))] = 0
		rangeNormalMap[utils.TimeToDayInt(utils.Str2Time(req.StartDay).AddDate(0, 0, i))] = 0
	}

	var AttackCountOfRange []model.StatsDayCount
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "阻止").Select("day,sum(count) as count").Group("day").Scan(&AttackCountOfRange)
	var NormalCountOfRange []model.StatsDayCount
	global.GWAF_LOCAL_DB.Debug().Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "放行").Select("day,sum(count) as count").Group("day").Scan(&NormalCountOfRange)

	for i := 0; i < len(AttackCountOfRange); i++ {
		bean := AttackCountOfRange[i]
		_, ok := rangeAttackMap[bean.Day]
		if ok {
			rangeAttackMap[bean.Day] = bean.Count
		}
	}
	for i := 0; i < len(NormalCountOfRange); i++ {
		bean := NormalCountOfRange[i]
		_, ok := rangeNormalMap[bean.Day]
		if ok {
			rangeNormalMap[bean.Day] = bean.Count
		}
	}
	return response2.WafStatRange{
			AttackCountOfRange: rangeAttackMap,
			NormalCountOfRange: rangeNormalMap,
		},
		nil
}
