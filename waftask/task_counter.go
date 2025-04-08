package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/service/waf_service"
	"fmt"
	"time"
)

var (
	wafSysLogService       = waf_service.WafSysLogServiceApp
	wafSystemConfigService = waf_service.WafSystemConfigServiceApp
	wafLogService          = waf_service.WafLogServiceApp
)

type LastCounter struct {
	UNIX_ADD_TIME int64 `json:"unix_add_time" gorm:"index"` //添加日期unix
}
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

type CountIPRuleResult struct {
	Ip   string `json:"ip"`   //用户ip
	Rule string `json:"rule"` //规则
	Cnt  int64  `json:"cnt"`  //数量
}

/**
定时统计
*/

func TaskCounter() {
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		zlog.Debug("数据库没有初始化完成呢")
		return
	}
	if global.GWAF_SWITCH_TASK_COUNTER == true {
		zlog.Debug("统计还没完成，调度任务PASS")
	}
	global.GWAF_SWITCH_TASK_COUNTER = true

	/**
	1.首次是当前日期，查询当前时间以后的所有数据，备份当前日期
	2.查询使用备份日期，倒退10秒，查询这个时候所有的数据
	3.

	*/
	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		zlog.Debug("正在切换数据库等待中")
		global.GWAF_SWITCH_TASK_COUNTER = false
		return
	}

	if global.GWAF_LAST_TIME_UNIX == 0 {
		global.GWAF_LAST_TIME_UNIX = (global.GWAF_LAST_UPDATE_TIME.UnixNano()) / 1e6
		global.GWAF_SWITCH_TASK_COUNTER = false
		return
	}
	//取大于上次时间的时
	statTimeUnix := global.GWAF_LAST_TIME_UNIX
	endTimeUnix := (time.Now().Add(-5 * time.Second).UnixNano()) / 1e6
	//打印 statTimeUnix，endTimeUnix
	zlog.Debug(fmt.Sprintf("counter statTimeUnix = %v endTimeUnix=%v", statTimeUnix, endTimeUnix))
	lastWebLogDbBean := wafLogService.GetUnixTimeByCounter(statTimeUnix, endTimeUnix)
	if lastWebLogDbBean.REQ_UUID == "" {
		zlog.Debug("当前期间没有符合条件的数据")
		global.GWAF_LAST_TIME_UNIX = endTimeUnix
		global.GWAF_SWITCH_TASK_COUNTER = false
		return
	} else {
		global.GWAF_LAST_TIME_UNIX = endTimeUnix
	}
	//一、 主机聚合统计
	{
		var resultHosts []CountHostResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host FROM \"web_logs\" where task_flag = ?  and unix_add_time >= ?  and unix_add_time < ? and tenant_id = ? and user_code =?  GROUP BY host_code, user_code,action,tenant_id,day,host",
			1, statTimeUnix, endTimeUnix, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Scan(&resultHosts)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultHosts {
			var statDay model.StatsDay
			global.GWAF_LOCAL_STATS_DB.Where("tenant_id = ? and user_code = ? and host_code=? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsDay{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					HostCode: value.HostCode,
					Day:      value.Day,
					Host:     value.Host,
					Type:     value.ACTION,
					Count:    value.Count,
				}
				global.GQEQUE_STATS_DB.Enqueue(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				}
				updateBean := innerbean.UpdateModel{
					Model:  model.StatsDay{},
					Query:  `tenant_id = ? and user_code= ? and host_code=? and type=? and day=?`,
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.Enqueue(updateBean)
			}
		}
	}

	//二、 IP聚合统计
	{
		var resultIP []CountIPResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,src_ip as ip FROM \"web_logs\" where task_flag = ?  and unix_add_time >= ?  and unix_add_time < ?  and tenant_id = ? and user_code =?  GROUP BY host_code, user_code,action,tenant_id,day,host,ip",
			1, statTimeUnix, endTimeUnix, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Scan(&resultIP)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultIP {
			var statDay model.StatsIPDay
			global.GWAF_LOCAL_STATS_DB.Where("tenant_id = ? and user_code = ? and host_code=? and ip = ? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.Ip, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsIPDay{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					HostCode: value.HostCode,
					Day:      value.Day,
					Host:     value.Host,
					Type:     value.ACTION,
					Count:    value.Count,
					IP:       value.Ip,
				}
				global.GQEQUE_STATS_DB.Enqueue(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				}

				updateBean := innerbean.UpdateModel{
					Model:  model.StatsIPDay{},
					Query:  "tenant_id = ? and user_code= ? and host_code=? and ip=? and type=? and day=?",
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.Ip, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.Enqueue(updateBean)

			}
		}
	}

	//三、 城市信息聚合统计
	{
		var resultCitys []CountCityResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,country,province,city  FROM \"web_logs\" where task_flag = ?  and unix_add_time >= ?   and unix_add_time < ? and tenant_id = ? and user_code =? GROUP BY host_code, user_code,action,tenant_id,day,host,country,province,city",
			1, statTimeUnix, endTimeUnix, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Scan(&resultCitys)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个周期的统计数
		*/
		for _, value := range resultCitys {
			var statDay model.StatsIPCityDay
			global.GWAF_LOCAL_STATS_DB.Where("tenant_id = ? and user_code = ? and host_code=? and country = ? and province = ? and city = ? and type=? and day=?",
				value.TenantId, value.UserCode, value.HostCode, value.Country, value.Province, value.City, value.ACTION, value.Day).Find(&statDay)

			if statDay.HostCode == "" {
				statDay2 := &model.StatsIPCityDay{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					HostCode: value.HostCode,
					Day:      value.Day,
					Host:     value.Host,
					Type:     value.ACTION,
					Count:    value.Count,
					Country:  value.Country,
					Province: value.Province,
					City:     value.City,
				}
				global.GQEQUE_STATS_DB.Enqueue(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				}

				updateBean := innerbean.UpdateModel{
					Model:  model.StatsIPCityDay{},
					Query:  "tenant_id = ? and user_code= ? and host_code=? and country = ? and province = ? and city = ? and type=? and day=?",
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.Country, value.Province, value.City, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.Enqueue(updateBean)

			}
		}
	}

	//第四 给IP打标签 开始
	{
		var resultIPRule []CountIPRuleResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT src_ip as ip ,rule,count(src_ip) as cnt  FROM \"web_logs\" where task_flag = ?  and unix_add_time >= ?  and unix_add_time < ?  and tenant_id = ? and user_code =? GROUP BY user_code,tenant_id, rule,src_ip",
			1, statTimeUnix, endTimeUnix, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Scan(&resultIPRule)
		/****
		1.如果不存在则创建
		2.如果存在则累加这个IP这个rule的统计数
		*/
		for _, value := range resultIPRule {
			if value.Rule == "" {
				value.Rule = "正常"
			}
			var ipTag model.IPTag
			global.GWAF_LOCAL_DB.Where("tenant_id = ? and user_code = ? and ip=? and ip_tag = ?",
				global.GWAF_TENANT_ID, global.GWAF_USER_CODE, value.Ip, value.Rule).Find(&ipTag)
			if ipTag.IP == "" {
				insertIpTag := &model.IPTag{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					IP:      value.Ip,
					IPTag:   value.Rule,
					Cnt:     value.Cnt,
					Remarks: "",
				}
				global.GQEQUE_DB.Enqueue(insertIpTag)
			} else {
				ipTagUpdateMap := map[string]interface{}{
					"Cnt":         value.Cnt + ipTag.Cnt,
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				}
				updateBean := innerbean.UpdateModel{
					Model:  model.IPTag{},
					Query:  "tenant_id = ? and user_code= ? and ip=? and ip_tag = ?",
					Update: ipTagUpdateMap,
				}
				updateBean.Args = append(updateBean.Args, global.GWAF_TENANT_ID, global.GWAF_USER_CODE, value.Ip, value.Rule)
				global.GQEQUE_UPDATE_DB.Enqueue(updateBean)
			}
		}

	} //给IP打标签结束
	global.GWAF_SWITCH_TASK_COUNTER = false
}
