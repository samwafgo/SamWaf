package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model/request"
	"strconv"
)

func setConfigIntValue(name string, value int64, change int) {
	// 更新全局配置值
	switch name {
	case "record_max_req_body_length":
		global.GCONFIG_RECORD_MAX_BODY_LENGTH = value
	case "record_max_res_body_length":
		global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = value
	case "record_resp":
		global.GCONFIG_RECORD_RESP = value
	case "delete_history_log_day":
		global.GDATA_DELETE_INTERVAL = value
	case "log_db_size":
		global.GDATA_SHARE_DB_SIZE = value
	case "auto_load_ssl_file":
		global.GCONFIG_RECORD_AUTO_LOAD_SSL = value
	case "kafka_enable":
		if global.GCONFIG_RECORD_KAFKA_ENABLE != value && global.GNOTIFY_KAKFA_SERVICE != nil {
			global.GNOTIFY_KAKFA_SERVICE.ChangeEnable(value)
		}
		global.GCONFIG_RECORD_KAFKA_ENABLE = value
	default:
		zlog.Warn("Unknown config item:", name)
	}
}

func setConfigStringValue(name string, value string, change int) {
	// 更新全局配置值
	switch name {
	case "dns_server":
		global.GWAF_RUNTIME_DNS_SERVER = value
	case "record_log_type":
		global.GWAF_RUNTIME_RECORD_LOG_TYPE = value
	case "gwaf_center_enable":
		global.GWAF_CENTER_ENABLE = value
	case "gwaf_center_url":
		global.GWAF_CENTER_URL = value
	case "gwaf_proxy_header":
		global.GCONFIG_RECORD_PROXY_HEADER = value
	case "kafka_url":
		global.GCONFIG_RECORD_KAFKA_URL = value
	case "kafka_topic":
		global.GCONFIG_RECORD_KAFKA_TOPIC = value
	default:
		zlog.Warn("Unknown config item:", name)
	}
}

func updateConfigIntItem(initLoad bool, itemClass string, itemName string, defaultValue int64, remarks string, itemType string, options string) {
	configItem := wafSystemConfigService.GetDetailByItem(itemName)
	if configItem.Id != "" {
		value, err := strconv.ParseInt(configItem.Value, 10, 0)
		if err == nil && defaultValue != value {
			setConfigIntValue(itemName, value, 1)
		} else if err == nil && initLoad == true {
			setConfigIntValue(itemName, value, 0)
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			ItemClass: itemClass,
			Item:      itemName,
			Value:     strconv.FormatInt(defaultValue, 10),
			Remarks:   remarks,
			ItemType:  itemType,
			Options:   options,
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
}
func updateConfigStringItem(initLoad bool, itemClass string, itemName string, defaultValue string, remarks string, itemType string, options string) {
	configItem := wafSystemConfigService.GetDetailByItem(itemName)
	if configItem.Id != "" {
		if defaultValue != configItem.Value {
			setConfigStringValue(itemName, configItem.Value, 1)
		} else if initLoad == true {
			setConfigStringValue(itemName, configItem.Value, 0)
		}
	} else {
		wafSystemConfigAddReq := request.WafSystemConfigAddReq{
			ItemClass: itemClass,
			Item:      itemName,
			Value:     defaultValue,
			Remarks:   remarks,
			ItemType:  itemType,
			Options:   options,
		}
		wafSystemConfigService.AddApi(wafSystemConfigAddReq)
	}
}

// 加载配置数据
func TaskLoadSetting(initLoad bool) {
	zlog.Debug("TaskLoadSetting")
	updateConfigIntItem(initLoad, "system", "record_max_req_body_length", global.GCONFIG_RECORD_MAX_BODY_LENGTH, "记录请求最大报文", "int", "")
	updateConfigIntItem(initLoad, "system", "record_max_res_body_length", global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH, "如果可以记录，满足最大响应报文大小才记录", "int", "")
	updateConfigIntItem(initLoad, "system", "record_resp", global.GCONFIG_RECORD_RESP, "是否记录响应报文", "int", "")
	updateConfigIntItem(initLoad, "system", "delete_history_log_day", global.GDATA_DELETE_INTERVAL, "删除多少天前的日志数据(单位:天)", "int", "")
	updateConfigIntItem(initLoad, "system", "log_db_size", global.GDATA_SHARE_DB_SIZE, "日志归档最大记录数量", "int", "")
	updateConfigIntItem(initLoad, "system", "auto_load_ssl_file", global.GCONFIG_RECORD_AUTO_LOAD_SSL, "是否每天凌晨3点自动加载ssl证书", "int", "")

	updateConfigStringItem(initLoad, "system", "dns_server", global.GWAF_RUNTIME_DNS_SERVER, "DNS服务器", "options", "119.29.29.29|腾讯DNS,8.8.8.8|谷歌DNS")
	updateConfigStringItem(initLoad, "system", "record_log_type", global.GWAF_RUNTIME_RECORD_LOG_TYPE, "日志记录类型", "options", "all|全部,abnormal|非正常")
	updateConfigStringItem(initLoad, "system", "gwaf_center_enable", global.GWAF_CENTER_ENABLE, "中心开关", "bool", "false|关闭,true|开启")
	updateConfigStringItem(initLoad, "system", "gwaf_center_url", global.GWAF_CENTER_URL, "中心URL", "string", "")
	updateConfigStringItem(initLoad, "system", "gwaf_proxy_header", global.GCONFIG_RECORD_PROXY_HEADER, "获取访客IP头信息（按照顺序）", "string", "")

	updateConfigIntItem(initLoad, "kafka", "kafka_enable", global.GCONFIG_RECORD_KAFKA_ENABLE, "kafka 是否激活", "int", "")
	updateConfigStringItem(initLoad, "kafka", "kafka_url", global.GCONFIG_RECORD_KAFKA_URL, "kafka url地址", "string", "")
	updateConfigStringItem(initLoad, "kafka", "kafka_topic", global.GCONFIG_RECORD_KAFKA_TOPIC, "kafka topic", "string", "")

}
