package waftask

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/wafdb"
	"SamWaf/wechat"
	"encoding/json"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"os"
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
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		zlog.Debug("数据库没有初始化完成呢")
		return
	}
	global.GWAF_SWITCH_TASK_COUNTER = true
	/*dateTime, err := time.Parse("2006-01-02", "2023-01-01")
	if err != nil {
		fmt.Println("解析日期出错:", err)
		return
	}
	currenyDayBak := dateTime*/

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
	currenyDayBak := time.Now()
	currenyDayMillisecondsBak := (global.GWAF_LAST_UPDATE_TIME.Add(-10 * time.Second).UnixNano()) / 1e6 //倒退10秒

	//一、 主机聚合统计
	{
		var resultHosts []CountHostResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host FROM \"web_logs\" where task_flag = ?  and unix_add_time > ? GROUP BY host_code, user_code,action,tenant_id,day,host",
			1, currenyDayMillisecondsBak).Scan(&resultHosts)
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
						Id:          uuid.NewV4().String(),
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
				global.GQEQUE_STATS_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(currenyDayBak),
				}
				updateBean := innerbean.UpdateModel{
					Model:  model.StatsDay{},
					Query:  `tenant_id = ? and user_code= ? and host_code=? and type=? and day=?`,
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.PushBack(updateBean)
			}
		}
	}

	//二、 IP聚合统计
	{
		var resultIP []CountIPResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,src_ip as ip FROM \"web_logs\" where task_flag = ?  and unix_add_time > ?  GROUP BY host_code, user_code,action,tenant_id,day,host,ip",
			1, currenyDayMillisecondsBak).Scan(&resultIP)
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
						Id:          uuid.NewV4().String(),
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
				global.GQEQUE_STATS_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(currenyDayBak),
				}

				updateBean := innerbean.UpdateModel{
					Model:  model.StatsIPDay{},
					Query:  "tenant_id = ? and user_code= ? and host_code=? and ip=? and type=? and day=?",
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.Ip, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.PushBack(updateBean)

			}
		}
	}

	//三、 城市信息聚合统计
	{
		var resultCitys []CountCityResult
		global.GWAF_LOCAL_LOG_DB.Raw("SELECT host_code, user_code,tenant_id ,action,count(req_uuid) as count,day,host,country,province,city  FROM \"web_logs\" where task_flag = ?  and unix_add_time > ? GROUP BY host_code, user_code,action,tenant_id,day,host,country,province,city",
			1, currenyDayMillisecondsBak).Scan(&resultCitys)
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
						Id:          uuid.NewV4().String(),
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
				global.GQEQUE_STATS_DB.PushBack(statDay2)
			} else {
				statDayMap := map[string]interface{}{
					"Count":       value.Count + statDay.Count,
					"UPDATE_TIME": customtype.JsonTime(currenyDayBak),
				}

				updateBean := innerbean.UpdateModel{
					Model:  model.StatsIPCityDay{},
					Query:  "tenant_id = ? and user_code= ? and host_code=? and country = ? and province = ? and city = ? and type=? and day=?",
					Update: statDayMap,
				}
				updateBean.Args = append(updateBean.Args, value.TenantId, value.UserCode, value.HostCode, value.Country, value.Province, value.City, value.ACTION, value.Day)
				global.GQEQUE_STATS_UPDATE_DB.PushBack(updateBean)

			}
		}
	}
	global.GWAF_LAST_UPDATE_TIME = currenyDayBak
	global.GWAF_SWITCH_TASK_COUNTER = false
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
			Item:     "record_max_req_body_length",
			Value:    strconv.FormatInt(global.GCONFIG_RECORD_MAX_BODY_LENGTH, 10),
			Remarks:  "记录请求最大报文",
			ItemType: "int",
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
			Item:     "record_max_rep_body_length",
			Value:    strconv.FormatInt(global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH, 10),
			Remarks:  "如果可以记录，满足最大响应报文大小才记录",
			ItemType: "int",
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
			Item:     "record_resp",
			Value:    strconv.FormatInt(global.GCONFIG_RECORD_RESP, 10),
			Remarks:  "是否记录响应报文",
			ItemType: "int",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
	configItem = wafSystemConfigService.GetDetailByItem("delete_history_log_day")
	if configItem.Id != "" {
		value, err := strconv.Atoi(configItem.Value)
		if err == nil {
			if global.GDATA_DELETE_INTERVAL != value {
				global.GDATA_DELETE_INTERVAL = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:     "delete_history_log_day",
			Value:    strconv.Itoa(global.GDATA_DELETE_INTERVAL),
			Remarks:  "删除多少天前的日志数据(单位:天)",
			ItemType: "int",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}

	configItem = wafSystemConfigService.GetDetailByItem("log_db_size")
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 64)
		if err == nil {
			if global.GDATA_SHARE_DB_SIZE != value {
				global.GDATA_SHARE_DB_SIZE = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:     "log_db_size",
			Value:    strconv.FormatInt(global.GDATA_SHARE_DB_SIZE, 10),
			Remarks:  "日志归档最大记录数量",
			ItemType: "int",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}

	//dns查询
	configItem = wafSystemConfigService.GetDetailByItem("dns_server")
	if configItem.Id != "" {
		if global.GWAF_RUNTIME_DNS_SERVER != configItem.Value {
			global.GWAF_RUNTIME_DNS_SERVER = configItem.Value
		}
	} else {
		wafSystemConfigService.AddApi(request.WafSystemConfigAddReq{
			Item:     "dns_server",
			Value:    global.GWAF_RUNTIME_DNS_SERVER,
			Remarks:  "DNS服务器",
			ItemType: "options",
			Options:  "119.29.29.29|腾讯DNS,8.8.8.8|谷歌DNS",
		})
	}

	//日志记录类型
	configItem = wafSystemConfigService.GetDetailByItem("record_log_type")
	if configItem.Id != "" {
		if global.GWAF_RUNTIME_RECORD_LOG_TYPE != configItem.Value {
			global.GWAF_RUNTIME_RECORD_LOG_TYPE = configItem.Value
		}
	} else {
		wafSystemConfigService.AddApi(request.WafSystemConfigAddReq{
			Item:     "record_log_type",
			Value:    global.GWAF_RUNTIME_RECORD_LOG_TYPE,
			Remarks:  "日志记录类型",
			ItemType: "options",
			Options:  "all|全部,abnormal|非正常",
		})
	}
}

/*
*
定时发送延迟信息
*/
func TaskDelayInfo() {
	zlog.Debug("TaskDelayInfo")

	models, count, err := waf_service.WafDelayMsgServiceApp.GetAllList()
	if err == nil {
		if count > 0 {
			for i := 0; i < len(models); i++ {
				msg := models[i]
				sendSuccess := 0
				//发送websocket
				for _, ws := range global.GWebSocket.SocketMap {
					if ws != nil {

						cmdType := "Info"
						if msg.DelayType == "升级结果" {
							cmdType = "RELOAD_PAGE"
						}
						//写入ws数据
						msgBytes, err := json.Marshal(
							model.MsgPacket{
								MsgCode: "200",
								MsgDataPacket: model.MsgDataPacket{
									MessageId:           uuid.NewV4().String(),
									MessageType:         msg.DelayType,
									MessageData:         msg.DelayContent,
									MessageAttach:       nil,
									MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
									MessageUnReadStatus: true,
								},
								MsgCmdType: cmdType,
							})
						err = ws.WriteMessage(1, msgBytes)
						if err != nil {
							continue
						} else {
							sendSuccess = sendSuccess + 1
						}
					}
				}

				if sendSuccess > 0 {
					waf_service.WafDelayMsgServiceApp.DelApi(msg.Id)
				}

			}
		}
	}
}

// 检测库是否切换
func TaskShareDbInfo() {
	zlog.Info("检测是否需要进行分库")
	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		zlog.Debug("切库状态")
		return
	}
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		zlog.Debug("数据库没有初始化完成呢")
		return
	}
	//获取当前日志数量
	var total int64 = 0
	global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&total)
	if total > global.GDATA_SHARE_DB_SIZE {
		global.GDATA_CURRENT_CHANGE = true
		oldDBFilename := "local_log.db"
		newDBFilename := fmt.Sprintf("local_log_%v.db", time.Now().Format("20060102150405"))

		var lastedDb model.ShareDb
		err := global.GWAF_LOCAL_DB.Limit(1).Order("create_time desc").Find(&lastedDb).Error
		startTime := customtype.JsonTime(time.Now())
		if err == nil {
			startTime = lastedDb.EndTime
		}
		sharDbBean := model.ShareDb{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.NewV4().String(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			DbLogicType: "log",
			StartTime:   startTime,
			EndTime:     customtype.JsonTime(time.Now()),
			FileName:    newDBFilename,
			Cnt:         total,
		}

		currentDir := utils.GetCurrentDir()
		oldDBFilename = currentDir + "/data/" + oldDBFilename
		newDBFilename = currentDir + "/data/" + newDBFilename
		zlog.Info("正在切库中...")
		sqlDB, err := global.GWAF_LOCAL_LOG_DB.DB()

		if err != nil {
			zlog.Error("切换关闭时候错误", err)
		} else {

			// 关闭数据库连接
			if err := sqlDB.Close(); err != nil {
				zlog.Error("切换关闭时候错误", err)
			}
		}
		var testTotal int64
		for {
			testError := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&testTotal).Error
			if testError != nil {
				zlog.Error("检测数据", testError)
				break
			}
			time.Sleep(1 * time.Second)
		}

		// 关闭与数据库相关的连接或程序
		// 重命名数据库文件
		if err := os.Rename(oldDBFilename, newDBFilename); err != nil {
			zlog.Error("Error renaming database file:", err)
		}

		// 重命名 .db-shm 文件
		if err := os.Rename(oldDBFilename+"-shm", newDBFilename+"-shm"); err != nil {
			zlog.Error("Error renaming .db-shm file:", err)
			// 如果有必要，可以选择回滚数据库文件的重命名

		}

		// 重命名 .db-wal 文件
		if err := os.Rename(oldDBFilename+"-wal", newDBFilename+"-wal"); err != nil {
			zlog.Error("Error renaming .db-wal file:", err)
			// 如果有必要，可以选择回滚数据库文件的重命名
		}
		global.GWAF_LOCAL_DB.Create(sharDbBean)
		global.GWAF_LOCAL_LOG_DB = nil
		wafdb.InitLogDb("")
		global.GDATA_CURRENT_CHANGE = false
		zlog.Info("切库完成...")
	}

}
