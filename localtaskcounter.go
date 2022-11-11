package main

import (
	"SamWaf/global"
	"SamWaf/model"
	"time"
)

type CountResult struct {
	UserCode string `json:"user_code"` //用户码（主要键）
	TenantId string `json:"tenant_id"` //租户ID（主要键）
	HostCode string `json:"host_code"` //主机ID （主要键）
	Day      int    `json:"day"`       //年月日（主要键）
	Host     string `json:"host"`      //域名
	ACTION   string `json:"action"`
	Count    int    `json:"count"` //数量
}

/**
定时统计
*/

func TaskCounter() {

	var result []CountResult
	global.GWAF_LOCAL_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host FROM \"web_logs\" where create_time>? GROUP BY host_code, user_code,action,tenant_id,day,host", global.GWAF_LAST_UPDATE_TIME.Format("2006-01-02 15:04:05")).Scan(&result)
	/****
	1.如果不存在则创建
	2.如果存在则累加这个周期的统计数
	*/
	for _, value := range result {
		var statDay model.StatsDay
		global.GWAF_LOCAL_DB.Where("host_code=? and type=? and day=?",
			value.HostCode, value.ACTION, value.Day).Find(&statDay)

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
			global.GWAF_LOCAL_DB.Debug().Create(statDay2)
		} else {
			statDayMap := map[string]interface{}{
				"Count":            value.Count + statDay.Count,
				"last_update_time": time.Now(),
			}

			global.GWAF_LOCAL_DB.Debug().Model(model.StatsDay{}).Where("host_code=? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day).Updates(statDayMap)

		}
	}
	global.GWAF_LAST_UPDATE_TIME = time.Now()
}
