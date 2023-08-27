package waftask

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils/zlog"
	"SamWaf/wechat"
	"fmt"
	"strconv"
	"time"
)

var (
	wafSysLogService       = waf_service.WafSysLogServiceApp
	wafSystemConfigService = waf_service.WafSystemConfigServiceApp
)

type CountHostResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}
type CountIPResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Ip       string `json:"ip"`        //域名
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}
type CountCityResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	Country  string `json:"country"`   //国家
	Province string `json:"province"`  //省份
	City     string `json:"city"`      //城市
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}

/**
定时统计
*/

func TaskCounter() {

	/*dateTime, err := time.Parse("2006-01-02", "2023-01-01")
	if err != nil {
		fmt.Println("解析日期出错:", err)
		return
	}
	currenyDayBak := dateTime*/

	currenyDayBak := time.Now()
	//一、 主机聚合统计
	{
		var resultHosts []CountHostResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host FROM \"web_logs\" where create_time>? GROUP BY host_code, user_code,action,tenant_id,day,host",
			global.GWAF_LAST_UPDATE_TIME.Format("2006-01-02 15:04:05")).Scan(&resultHosts)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultHosts {
			var statDay model.StatsDay
			global.GWAF_LOCAL_LOG_DB.Where("tenant_id = ? and user_code = ? and host_code=? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsDay{
					UserCode:       value.UserCode,
					TenantId:       value.TenantId,
					HostCode:       value.HostCode,
					Day:            value.Day,
					Host:           value.Host,
					Type:           value.ACTION,
					Count:          value.Count,
					CreateTime:     time.Now(),
					LastUpdateTime: time.Now(),
				}
				global.GQEQUE_LOG_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":            value.Count + statDay.Count,
					"last_update_time": currenyDayBak,
				}

				global.GWAF_LOCAL_LOG_DB.Model(model.StatsDay{}).Where("tenant_id = ? and user_code= ? and host_code=? and type=? and day=?",
					value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day).Updates(statDayMap)
			}
		}
	}

	//二、 IP聚合统计
	{
		var resultIP []CountIPResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,src_ip as ip FROM \"web_logs\" where create_time>? GROUP BY host_code, user_code,action,tenant_id,day,host,ip",
			global.GWAF_LAST_UPDATE_TIME.Format("2006-01-02 15:04:05")).Scan(&resultIP)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultIP {
			var statDay model.StatsIPDay
			global.GWAF_LOCAL_LOG_DB.Where("tenant_id = ? and user_code = ? and host_code=? and ip = ? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.Ip, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsIPDay{
					UserCode:       value.UserCode,
					TenantId:       value.TenantId,
					HostCode:       value.HostCode,
					Day:            value.Day,
					Host:           value.Host,
					Type:           value.ACTION,
					Count:          value.Count,
					IP:             value.Ip,
					CreateTime:     time.Now(),
					LastUpdateTime: time.Now(),
				}
				global.GQEQUE_LOG_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":            value.Count + statDay.Count,
					"last_update_time": currenyDayBak,
				}

				global.GWAF_LOCAL_LOG_DB.Model(model.StatsIPDay{}).Where("tenant_id = ? and user_code= ? and host_code=? and ip=? and type=? and day=?",
					value.TenantId, value.UserCode, value.HostCode, value.Ip, value.ACTION, value.Day).Updates(statDayMap)
			}
		}
	}

	//三、 城市信息聚合统计
	{
		var resultCitys []CountCityResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,country,province,city  FROM \"web_logs\" where create_time>? GROUP BY host_code, user_code,action,tenant_id,day,host,country,province,city",
			global.GWAF_LAST_UPDATE_TIME.Format("2006-01-02 15:04:05")).Scan(&resultCitys)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultCitys {
			var statDay model.StatsIPCityDay
			global.GWAF_LOCAL_LOG_DB.Where("tenant_id = ? and user_code = ? and host_code=? and country = ? and province = ? and city = ? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.Country, value.Province, value.City, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsIPCityDay{
					UserCode:       value.UserCode,
					TenantId:       value.TenantId,
					HostCode:       value.HostCode,
					Day:            value.Day,
					Host:           value.Host,
					Type:           value.ACTION,
					Count:          value.Count,
					Country:        value.Country,
					Province:       value.Province,
					City:           value.City,
					CreateTime:     time.Now(),
					LastUpdateTime: time.Now(),
				}
				global.GQEQUE_LOG_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":            value.Count + statDay.Count,
					"last_update_time": currenyDayBak,
				}

				global.GWAF_LOCAL_LOG_DB.Model(model.StatsIPDay{}).Where("tenant_id = ? and user_code= ? and host_code=? and country = ? and province = ? and city = ? and type=? and day=?",
					value.TenantId, value.UserCode, value.HostCode, value.Country, value.Province, value.City, value.ACTION, value.Day).Updates(statDayMap)
			}
		}
	}
	global.GWAF_LAST_UPDATE_TIME = currenyDayBak
}

func TaskWechatAccessToken() {
	zlog.Debug("TaskWechatAccessToken")
	wr, err := wechat.GetAppAccessToken("wx8640c6a135dc4b55", "eb57b4a6c445d3624bac7fa3e85efbaf")
	if err != nil {
		zlog.Error("请求错误GetAppAccessToken")
	} else if wr.ErrCode != 0 {
		zlog.Error("Wechat Server:", wr.ErrMsg)
	} else {
		global.GCACHE_WECHAT_ACCESS = wr.AccessToken
		zlog.Debug("TaskWechatAccessToken获取到最新token:" + global.GCACHE_WECHAT_ACCESS)
	}

}

func TaskStatusNotify() {
	zlog.Debug("TaskStatusNotify")
	statHomeInfo, err := waf_service.WafStatServiceApp.StatHomeSumDayApi()
	if err == nil {
		noticeStr := fmt.Sprintf("今日访问量：%d 今天恶意访问量:%d 昨日恶意访问量:%d", statHomeInfo.VisitCountOfToday, statHomeInfo.AttackCountOfToday, statHomeInfo.AttackCountOfYesterday)

		global.GQEQUE_MESSAGE_DB.PushBack(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "汇总通知"},
			OperaCnt:        noticeStr,
		})
	} else {
		zlog.Error("TaskStatusNotifyerror", err)
	}

}

/*
*
定时删除指定历史信息 通过开关操作
*/
func TaskDeleteHistoryInfo() {
	zlog.Debug("TaskDeleteHistoryInfo")
	configItem := wafSystemConfigService.GetDetailByItem("delete_history_log_day")
	if configItem.Id != "" {
		value, err := strconv.Atoi(configItem.Value)
		if err == nil {
			if global.GDATA_DELETE_INTERVAL != value {
				global.GDATA_DELETE_INTERVAL = value
			}
		}
	}
	deleteBeforeDay := time.Now().AddDate(0, 0, -global.GDATA_DELETE_INTERVAL).Format("2006-01-02 15:04")
	waf_service.WafLogServiceApp.DeleteHistory(deleteBeforeDay)
}

// 加载配置数据
func TaskLoadSetting() {
	zlog.Debug("TaskLoadSetting")
	configItem := wafSystemConfigService.GetDetailByItem("record_max_req_body_length")
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 0)
		if err == nil {
			if global.GCONFIG_RECORD_MAX_BODY_LENGTH != value {
				global.GCONFIG_RECORD_MAX_BODY_LENGTH = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:    "record_max_req_body_length",
			Value:   strconv.FormatInt(global.GCONFIG_RECORD_MAX_BODY_LENGTH, 10),
			Remarks: "自动添加",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}

	configItem = wafSystemConfigService.GetDetailByItem("record_max_rep_body_length")
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 0)
		if err == nil {
			if global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH != value {
				global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:    "record_max_rep_body_length",
			Value:   strconv.FormatInt(global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH, 10),
			Remarks: "自动添加",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
	configItem = wafSystemConfigService.GetDetailByItem("record_resp")
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 0)
		if err == nil {
			if global.GCONFIG_RECORD_RESP != value {
				global.GCONFIG_RECORD_RESP = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:    "record_resp",
			Value:   strconv.FormatInt(global.GCONFIG_RECORD_RESP, 10),
			Remarks: "自动添加",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
}
