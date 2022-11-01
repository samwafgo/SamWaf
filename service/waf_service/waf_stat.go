package waf_service

import response2 "SamWaf/model/response"

type WafStatService struct{}

var WafStatServiceApp = new(WafStatService)

func (receiver *WafStatService) StatHomeApi() (response2.WafStat, error) {

	return response2.WafStat{
			AttackCountOfToday:          0,
			VisitCountOfToday:           0,
			AttackCountOfYesterday:      0,
			VisitCountOfYesterday:       0,
			AttackCountOfLastWeekToday:  0,
			VisitCountOfLastWeekToday:   0,
			NormalIpCountOfToday:        0,
			IllegalIpCountOfToday:       0,
			NormalCountryCountOfToday:   0,
			IllegalCountryCountOfToday:  0,
			NormalProvinceCountOfToday:  0,
			IllegalProvinceCountOfToday: 0,
			NormalCityCountOfToday:      0,
			IllegalCityCountOfToday:     0,
		},
		nil
}
