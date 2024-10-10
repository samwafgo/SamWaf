package waftask

import (
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/utils/zlog"
	"strconv"
)

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
	//控制中心-开关
	configItem = wafSystemConfigService.GetDetailByItem("gwaf_center_enable")
	if configItem.Id != "" {
		if global.GWAF_CENTER_ENABLE != configItem.Value {
			global.GWAF_CENTER_ENABLE = configItem.Value
		}
	} else {
		wafSystemConfigService.AddApi(request.WafSystemConfigAddReq{
			Item:     "gwaf_center_enable",
			Value:    global.GWAF_CENTER_ENABLE,
			Remarks:  "中心开关",
			ItemType: "bool",
			Options:  "false|关闭,true|开启",
		})
	}
	//控制中心-中心url
	configItem = wafSystemConfigService.GetDetailByItem("gwaf_center_url")
	if configItem.Id != "" {
		if global.GWAF_CENTER_URL != configItem.Value {
			global.GWAF_CENTER_URL = configItem.Value
		}
	} else {
		wafSystemConfigService.AddApi(request.WafSystemConfigAddReq{
			Item:     "gwaf_center_url",
			Value:    global.GWAF_CENTER_URL,
			Remarks:  "中心URL",
			ItemType: "string",
			Options:  "",
		})
	}
	//获取用户IP头方式
	configItem = wafSystemConfigService.GetDetailByItem("gwaf_proxy_header")
	if configItem.Id != "" {
		if global.GCONFIG_RECORD_PROXY_HEADER != configItem.Value {
			global.GCONFIG_RECORD_PROXY_HEADER = configItem.Value
		}
	} else {
		wafSystemConfigService.AddApi(request.WafSystemConfigAddReq{
			Item:     "gwaf_proxy_header",
			Value:    global.GCONFIG_RECORD_PROXY_HEADER,
			Remarks:  "获取访客IP头信息（按照顺序）",
			ItemType: "string",
			Options:  "",
		})
	}
	//是否每天凌晨3点自动加载ssl证书
	configItem = wafSystemConfigService.GetDetailByItem("auto_load_ssl_file")
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 0)
		if err == nil {
			if global.GCONFIG_RECORD_AUTO_LOAD_SSL != value {
				global.GCONFIG_RECORD_AUTO_LOAD_SSL = value
			}
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			Item:     "auto_load_ssl_file",
			Value:    strconv.FormatInt(global.GCONFIG_RECORD_AUTO_LOAD_SSL, 10),
			Remarks:  "是否每天凌晨3点自动加载ssl证书",
			ItemType: "int",
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
}
