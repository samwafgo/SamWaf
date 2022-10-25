package response

type WafStat struct {
	AttackCountOfToday          int64 //今日攻击数量
	VisitCountOfToday           int64 //今天访问数量
	AttackCountOfYesterday      int64 //昨日攻击数量
	VisitCountOfYesterday       int64 //昨日访问数量
	AttackCountOfLastWeekToday  int64 //上周攻击数量
	VisitCountOfLastWeekToday   int64 //上周访问数量
	NormalIpCountOfToday        int64 //今日正常IP数量
	IllegalIpCountOfToday       int64 //今日非法IP数量
	NormalCountryCountOfToday   int64 //今日正常国家数量
	IllegalCountryCountOfToday  int64 //今日非法国家数量
	NormalProvinceCountOfToday  int64 //今日正常省份数量
	IllegalProvinceCountOfToday int64 //今日非法省份数量
	NormalCityCountOfToday      int64 //今日正常城市数量
	IllegalCityCountOfToday     int64 //今日非法城市数量
}
