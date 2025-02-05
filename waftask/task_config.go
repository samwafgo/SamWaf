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
	case "redirect_https_code":
		global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE = value
		break
	case "login_max_error_time":
		global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME = value
		break
	case "login_limit_mintutes":
		global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES = value
		break
	case "enable_owasp":
		global.GCONFIG_RECORD_ENABLE_OWASP = value
		break
	case "enable_http_80":
		global.GCONFIG_RECORD_ENABLE_HTTP_80 = value
		break
	case "sslorder_expire_day":
		global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY = value
		break
	case "connect_time_out":
		global.GCONFIG_RECORD_CONNECT_TIME_OUT = value
		break
	case "keepalive_time_out":
		global.GCONFIG_RECORD_KEEPALIVE_TIME_OUT = value
		break
	case "record_all_src_byte_info":
		global.GCONFIG_RECORD_ALL_SRC_BYTE_INFO = value
		break
	case "token_expire_time":
		global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES = value
		break
	case "spider_deny":
		global.GCONFIG_RECORD_SPIDER_DENY = value
		break
	case "enable_debug":
		global.GCONFIG_RECORD_DEBUG_ENABLE = value
		break
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
	case "debug_pwd":
		global.GCONFIG_RECORD_DEBUG_PWD = value

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

// TaskLoadSettingCron 不是初始化加载
func TaskLoadSettingCron() {
	TaskLoadSetting(false)
}

// TaskLoadSetting 加载配置数据
//
//	initLoad true 是初始化加载，false不是初始化加载
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
	updateConfigStringItem(initLoad, "system", "gwaf_proxy_header", global.GCONFIG_RECORD_PROXY_HEADER, "获取访客IP头信息（按照顺序）比如:X-Forwarded-For,X-Real-IP ,留空则提取的是直接访客IP", "string", "")

	updateConfigIntItem(initLoad, "kafka", "kafka_enable", global.GCONFIG_RECORD_KAFKA_ENABLE, "kafka 是否激活", "int", "")
	updateConfigStringItem(initLoad, "kafka", "kafka_url", global.GCONFIG_RECORD_KAFKA_URL, "kafka url地址", "string", "")
	updateConfigStringItem(initLoad, "kafka", "kafka_topic", global.GCONFIG_RECORD_KAFKA_TOPIC, "kafka topic", "string", "")

	updateConfigIntItem(initLoad, "system", "redirect_https_code", global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE, "80重定向https时候跳转代码", "int", "")
	updateConfigIntItem(initLoad, "system", "login_max_error_time", global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME, "登录周期里错误最大次数 请大于0 ", "int", "")
	updateConfigIntItem(initLoad, "system", "login_limit_mintutes", global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES, "登录错误记录周期 单位分钟数，默认1分钟", "int", "")
	updateConfigIntItem(initLoad, "system", "enable_owasp", global.GCONFIG_RECORD_ENABLE_OWASP, "启动OWASP数据检测（1启动 0关闭）", "int", "")

	updateConfigIntItem(initLoad, "ssl", "enable_http_80", global.GCONFIG_RECORD_ENABLE_HTTP_80, "启动80端口服务（为自动申请证书使用 HTTP文件验证类型需要，DNS验证不需要）", "int", "")
	updateConfigIntItem(initLoad, "ssl", "sslorder_expire_day", global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY, "自动续期检测小于多少天开始发起自动申请 默认30天", "int", "")

	updateConfigIntItem(initLoad, "network", "connect_time_out", global.GCONFIG_RECORD_CONNECT_TIME_OUT, "连接超时（默认30s）", "int", "")
	updateConfigIntItem(initLoad, "network", "keepalive_time_out", global.GCONFIG_RECORD_KEEPALIVE_TIME_OUT, "保持活动超时（默认30s）", "int", "")

	updateConfigIntItem(initLoad, "system", "record_all_src_byte_info", global.GCONFIG_RECORD_ALL_SRC_BYTE_INFO, "启动记录原始请求BODY报文（1启动 0关闭）", "int", "")
	updateConfigIntItem(initLoad, "system", "token_expire_time", global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES, "管理平台令牌有效期，单位分钟（默认5分钟）", "int", "")
	updateConfigIntItem(initLoad, "system", "spider_deny", global.GCONFIG_RECORD_SPIDER_DENY, "爬虫禁止访问开关 默认 0 只检测不阻止访问 1 检测并阻止访问）", "int", "")
	updateConfigIntItem(initLoad, "debug", "enable_debug", global.GCONFIG_RECORD_DEBUG_ENABLE, "调试开关 默认关闭", "int", "")
	updateConfigStringItem(initLoad, "debug", "debug_pwd", global.GCONFIG_RECORD_DEBUG_PWD, "调试密码 如果未空则不需要密码", "string", "")

}
