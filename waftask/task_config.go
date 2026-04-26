package waftask

import (
	"SamWaf/common/tasklog"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/iplocation"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafipban"
	"SamWaf/wafnotify/logfilewriter"
	"SamWaf/wafowasp"
	"strconv"
)

// syncLogFileWriterConfig 将最新的全局配置同步到 LogFileWriter 实例
func syncLogFileWriterConfig() {
	if global.GNOTIFY_LOG_FILE_WRITER == nil {
		return
	}
	notifier := global.GNOTIFY_LOG_FILE_WRITER.GetNotifier()
	if notifier == nil {
		return
	}
	if writer, ok := notifier.(*logfilewriter.LogFileWriter); ok {
		writer.UpdateConfig(
			global.GCONFIG_LOG_FILE_WRITE_PATH,
			global.GCONFIG_LOG_FILE_WRITE_FORMAT,
			global.GCONFIG_LOG_FILE_WRITE_CUSTOM_TPL,
			global.GCONFIG_LOG_FILE_WRITE_MAX_SIZE,
			int(global.GCONFIG_LOG_FILE_WRITE_MAX_BACKUPS),
			int(global.GCONFIG_LOG_FILE_WRITE_MAX_DAYS),
			global.GCONFIG_LOG_FILE_WRITE_COMPRESS == 1,
		)
	}
}

func setConfigIntValue(name string, value int64, change int) {
	// 更新全局配置值
	switch name {
	case "record_max_req_body_length":
		global.GCONFIG_RECORD_MAX_BODY_LENGTH = value
		break
	case "record_max_res_body_length":
		global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = value
		break
	case "record_resp":
		global.GCONFIG_RECORD_RESP = value
		break
	case "delete_history_log_day":
		global.GDATA_DELETE_INTERVAL = value
		break
	case "log_db_size":
		global.GDATA_SHARE_DB_SIZE = value
		break
	case "db_file_size":
		global.GDATA_SHARE_DB_FILE_SIZE = value
		break
	case "auto_load_ssl_file":
		global.GCONFIG_RECORD_AUTO_LOAD_SSL = value
		break
	case "kafka_enable":
		if global.GCONFIG_RECORD_KAFKA_ENABLE != value && global.GNOTIFY_KAKFA_SERVICE != nil {
			global.GNOTIFY_KAKFA_SERVICE.ChangeEnable(value)
		}
		global.GCONFIG_RECORD_KAFKA_ENABLE = value
		break
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
	case "owasp_block_threshold":
		if value <= 0 {
			value = 7
		}
		global.GCONFIG_OWASP_BLOCK_THRESHOLD = value
		break
	case "enable_http_80":
		global.GCONFIG_RECORD_ENABLE_HTTP_80 = value
		break
	case "sslorder_expire_day":
		global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY = value
		break
	case "ssl_ip_expire_day":
		global.GCONFIG_RECORD_SSL_IP_EXPIRE_DAY = value
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
	case "dns_timeout":
		global.GWAF_RUNTIME_DNS_TIMEOUT = value
		break
	case "hide_server_header":
		global.GCONFIG_RECORD_HIDE_SERVER_HEADER = value
		break
	case "force_bind_2fa":
		global.GCONFIG_RECORD_FORCE_BIND_2FA = value
		break
	case "fake_spider_captcha":
		global.GCONFIG_RECORD_FAKE_SPIDER_CAPTCHA = value
		break
	case "sslhttp_check":
		global.GCONFIG_RECORD_SSLHTTP_CHECK = value
		break
	case "enable_https_redirect":
		global.GCONFIG_ENABLE_HTTPS_REDIRECT = value
		break
	case "enable_device_fingerprint":
		global.GCONFIG_ENABLE_DEVICE_FINGERPRINT = value
		break
	case "enable_strict_ip_binding":
		global.GCONFIG_ENABLE_STRICT_IP_BINDING = value
		break
	case "batch_insert":
		global.GDATA_BATCH_INSERT = value
		break
	case "log_persist_enable":
		global.GCONFIG_LOG_PERSIST_ENABLED = value
		break
	case "enable_proxy_protocol":
		global.GCONFIG_ENABLE_PROXY_PROTOCOL = value
		break
	case "enable_system_stats_push":
		global.GCONFIG_ENABLE_SYSTEM_STATS_PUSH = value
		break
	case "ip_tag_db":
		global.GDATA_IP_TAG_DB = value
		break
	case "ip_failure_ban_enabled":
		global.GCONFIG_IP_FAILURE_BAN_ENABLED = value
		break
	case "ip_failure_ban_lock_time":
		global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = value
		break
	case "check_beta_version":
		global.GCONFIG_CHECK_BETA_VERSION = value
		break
	case "http3":
		global.GCONFIG_ENABLE_HTTP3 = value
	case "record_log_desensitize":
		global.GCONFIG_RECORD_LOG_DESENSITIZE = value
	case "log_file_write_enable":
		if global.GCONFIG_LOG_FILE_WRITE_ENABLE != value && global.GNOTIFY_LOG_FILE_WRITER != nil {
			global.GNOTIFY_LOG_FILE_WRITER.ChangeEnable(value)
		}
		global.GCONFIG_LOG_FILE_WRITE_ENABLE = value
	case "log_file_write_max_size":
		global.GCONFIG_LOG_FILE_WRITE_MAX_SIZE = value
		syncLogFileWriterConfig()
	case "log_file_write_max_backups":
		global.GCONFIG_LOG_FILE_WRITE_MAX_BACKUPS = value
		syncLogFileWriterConfig()
	case "log_file_write_max_days":
		global.GCONFIG_LOG_FILE_WRITE_MAX_DAYS = value
		syncLogFileWriterConfig()
	case "log_file_write_compress":
		global.GCONFIG_LOG_FILE_WRITE_COMPRESS = value
		syncLogFileWriterConfig()
	case "open_platform_enabled":
		global.GCONFIG_OPEN_PLATFORM_ENABLED = value
	case "task_log_retain_days":
		global.GCONFIG_TASK_LOG_RETAIN_DAYS = value
		// 动态更新任务日志管理器的保留天数
		if tasklog.GlobalTaskLogManager != nil {
			tasklog.GlobalTaskLogManager.UpdateRetainDays(int(value))
		}
	case "http3_bbr":
		global.GCONFIG_ENABLE_HTTP3_BBR = value
	default:
		zlog.Warn("Unknown config item:", name)
	}
}

func setConfigStringValue(name string, value string, change int) {
	// 更新全局配置值
	switch name {
	case "dns_server":
		global.GWAF_RUNTIME_DNS_SERVER = value
		break
	case "record_log_type":
		global.GWAF_RUNTIME_RECORD_LOG_TYPE = value
		break
	case "gwaf_center_enable":
		global.GWAF_CENTER_ENABLE = value
		break
	case "gwaf_center_url":
		global.GWAF_CENTER_URL = value
		break
	case "gwaf_proxy_header":
		global.GCONFIG_RECORD_PROXY_HEADER = value
		break
	case "owasp_mode":
		switch value {
		case "On", "DetectionOnly", "Off":
			global.GCONFIG_OWASP_MODE = value
		case "":
			global.GCONFIG_OWASP_MODE = "On"
		default:
			zlog.Warn("invalid owasp_mode value, fallback to On", value)
			global.GCONFIG_OWASP_MODE = "On"
		}
		// 同步到 wafowasp 热路径，使 DetectionOnly "本该拦截" 的 INFO 日志能按当前模式生效
		wafowasp.SetEngineMode(global.GCONFIG_OWASP_MODE)
		break
	case "kafka_url":
		global.GCONFIG_RECORD_KAFKA_URL = value
		break
	case "kafka_topic":
		global.GCONFIG_RECORD_KAFKA_TOPIC = value
		break
	case "debug_pwd":
		global.GCONFIG_RECORD_DEBUG_PWD = value
		break
	case "gpt_url":
		global.GCONFIG_RECORD_GPT_URL = value
		break
	case "gpt_token":
		global.GCONFIG_RECORD_GPT_TOKEN = value
		break
	case "gpt_model":
		global.GCONFIG_RECORD_GPT_MODEL = value
		break
	case "ssl_min_version":
		global.GCONFIG_RECORD_SSLMinVerson = value
		break
	case "ssl_max_version":
		global.GCONFIG_RECORD_SSLMaxVerson = value
		break
	case "ssl_ip_cert_ip":
		global.GCONFIG_RECORD_SSL_IP_CERT_IP = value
		break
	case "ip_failure_status_codes":
		global.GCONFIG_IP_FAILURE_STATUS_CODES = value
		// 重新加载状态码配置
		wafipban.GetIPFailureManager().ReloadStatusCodes()
		break
	case "zerossl_access_key":
		global.GCONFIG_ZEROSSL_ACCESS_KEY = value
		break
	case "zerossl_eab_kid":
		global.GCONFIG_ZEROSSL_EAB_KID = value
		break
	case "zerossl_eab_hmac_key":
		global.GCONFIG_ZEROSSL_EAB_HMAC_KEY = value
		break
	case "log_file_write_path":
		global.GCONFIG_LOG_FILE_WRITE_PATH = value
		syncLogFileWriterConfig()
	case "log_file_write_format":
		global.GCONFIG_LOG_FILE_WRITE_FORMAT = value
		syncLogFileWriterConfig()
	case "log_file_write_custom_tpl":
		global.GCONFIG_LOG_FILE_WRITE_CUSTOM_TPL = value
		syncLogFileWriterConfig()
	case "ip_v4_source":
		global.GCONFIG_IP_V4_SOURCE = value
		if change == 1 {
			zlog.Info("IPv4 数据源配置已更改为: ", value)
		}
	case "ip_v6_source":
		global.GCONFIG_IP_V6_SOURCE = value
		if change == 1 {
			zlog.Info("IPv6 数据源配置已更改为: ", value)
		}
	case "ip_v4_format":
		global.GCONFIG_IP_V4_FORMAT = value
		if change == 1 {
			// 重新加载 IPv4 数据库
			if global.GIPLOCATION_MANAGER != nil {
				global.GIPLOCATION_MANAGER.SetV4Format(iplocation.DBFormat(value))
				zlog.Info("IPv4 数据格式配置已更改为: ", value)
			}
		}
	case "ip_v6_format":
		global.GCONFIG_IP_V6_FORMAT = value
		if change == 1 {
			// 重新加载 IPv6 数据库
			if global.GIPLOCATION_MANAGER != nil {
				global.GIPLOCATION_MANAGER.SetV6Format(iplocation.DBFormat(value))
				zlog.Info("IPv6 数据格式配置已更改为: ", value)
			}
		}
	default:
		zlog.Warn("Unknown config item:", name)
	}
}

func updateConfigIntItem(initLoad bool, itemClass string, itemName string, defaultValue int64, remarks string, itemType string, options string, configMap map[string]model.SystemConfig) {
	configItem, exists := configMap[itemName]
	if exists && configItem.Id != "" {
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
func updateConfigStringItem(initLoad bool, itemClass string, itemName string, defaultValue string, remarks string, itemType string, options string, configMap map[string]model.SystemConfig) {
	configItem, exists := configMap[itemName]
	if exists && configItem.Id != "" {
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

	// 一次性批量查询所有配置项
	configMap := wafSystemConfigService.GetAllConfigs()

	updateConfigIntItem(initLoad, "system", "record_max_req_body_length", global.GCONFIG_RECORD_MAX_BODY_LENGTH, "记录请求最大报文", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "record_max_res_body_length", global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH, "如果可以记录，满足最大响应报文大小才记录", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "record_resp", global.GCONFIG_RECORD_RESP, "是否记录响应报文", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "delete_history_log_day", global.GDATA_DELETE_INTERVAL, "删除多少天前的日志数据(单位:天)", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "log_db_size", global.GDATA_SHARE_DB_SIZE, "日志归档最大记录数量", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "db_file_size", global.GDATA_SHARE_DB_FILE_SIZE, "日志归档最大文件大小(MB)", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "auto_load_ssl_file", global.GCONFIG_RECORD_AUTO_LOAD_SSL, "是否每天凌晨3点自动加载ssl证书", "int", "", configMap)

	updateConfigStringItem(initLoad, "system", "dns_server", global.GWAF_RUNTIME_DNS_SERVER, "DNS服务器", "options", "119.29.29.29|腾讯DNS,8.8.8.8|谷歌DNS", configMap)
	updateConfigIntItem(initLoad, "system", "dns_timeout", global.GWAF_RUNTIME_DNS_TIMEOUT, "DNS 查询超时时间 单位毫秒", "int", "", configMap)

	updateConfigStringItem(initLoad, "system", "record_log_type", global.GWAF_RUNTIME_RECORD_LOG_TYPE, "日志记录类型", "options", "all|全部,abnormal|非正常", configMap)
	updateConfigStringItem(initLoad, "system", "gwaf_center_enable", global.GWAF_CENTER_ENABLE, "中心开关", "bool", "false|关闭,true|开启", configMap)
	updateConfigStringItem(initLoad, "system", "gwaf_center_url", global.GWAF_CENTER_URL, "中心URL", "string", "", configMap)
	updateConfigStringItem(initLoad, "system", "gwaf_proxy_header", global.GCONFIG_RECORD_PROXY_HEADER, "获取访客IP头信息（按照顺序）比如:X-Forwarded-For,X-Real-IP ,留空则提取的是直接访客IP", "string", "", configMap)

	updateConfigIntItem(initLoad, "kafka", "kafka_enable", global.GCONFIG_RECORD_KAFKA_ENABLE, "kafka 是否激活", "int", "", configMap)
	updateConfigStringItem(initLoad, "kafka", "kafka_url", global.GCONFIG_RECORD_KAFKA_URL, "kafka url地址", "string", "", configMap)
	updateConfigStringItem(initLoad, "kafka", "kafka_topic", global.GCONFIG_RECORD_KAFKA_TOPIC, "kafka topic", "string", "", configMap)

	updateConfigIntItem(initLoad, "system", "redirect_https_code", global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE, "80重定向https时候跳转代码", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "enable_https_redirect", global.GCONFIG_ENABLE_HTTPS_REDIRECT, "是否启用HTTPS重定向服务器（0关闭 1开启）", "int", "", configMap)

	updateConfigIntItem(initLoad, "system", "login_max_error_time", global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME, "登录周期里错误最大次数 请大于0 ", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "login_limit_mintutes", global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES, "登录错误记录周期 单位分钟数，默认1分钟", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "enable_owasp", global.GCONFIG_RECORD_ENABLE_OWASP, "启动OWASP数据检测（1启动 0关闭）", "int", "", configMap)

	updateConfigIntItem(initLoad, "ssl", "enable_http_80", global.GCONFIG_RECORD_ENABLE_HTTP_80, "启动80端口服务（为自动申请证书使用 HTTP文件验证类型需要，DNS验证不需要）", "int", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "sslorder_expire_day", global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY, "自动续期检测小于多少天开始发起自动申请 默认30天", "int", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_ip_cert_ip", global.GCONFIG_RECORD_SSL_IP_CERT_IP, "获取IP证书时的IP地址（为IP证书申请使用，留空则不使用）", "string", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "ssl_ip_expire_day", global.GCONFIG_RECORD_SSL_IP_EXPIRE_DAY, "IP证书自动续期检测小于多少天开始发起自动申请 默认3天", "int", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "sslhttp_check", global.GCONFIG_RECORD_SSLHTTP_CHECK, "证书文件验证方式是否要严控后端.well-known 响应代码必须是404 301 302 ，默认1控制 0 不控制", "int", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_min_version", global.GCONFIG_RECORD_SSLMinVerson, "SSL最低版本(支持TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3)，修改后重启一下", "options", "TLS 1.0|TLS 1.0,TLS 1.1|TLS 1.1,TLS 1.2|TLS 1.2,TLS 1.3|TLS 1.3", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_max_version", global.GCONFIG_RECORD_SSLMaxVerson, "SSL最大版本(支持TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3)，修改后重启一下", "options", "TLS 1.0|TLS 1.0,TLS 1.1|TLS 1.1,TLS 1.2|TLS 1.2,TLS 1.3|TLS 1.3", configMap)

	updateConfigIntItem(initLoad, "network", "connect_time_out", global.GCONFIG_RECORD_CONNECT_TIME_OUT, "连接超时（默认30s）", "int", "", configMap)
	updateConfigIntItem(initLoad, "network", "keepalive_time_out", global.GCONFIG_RECORD_KEEPALIVE_TIME_OUT, "保持活动超时（默认30s）", "int", "", configMap)
	updateConfigIntItem(initLoad, "network", "http3", global.GCONFIG_ENABLE_HTTP3, "是否启用http3（1启用 0关闭）", "int", "", configMap)
	updateConfigIntItem(initLoad, "network", "http3_bbr", global.GCONFIG_ENABLE_HTTP3_BBR, "配置http3是否用BBR(默认NewReno)", "int", "", configMap)

	updateConfigIntItem(initLoad, "system", "record_all_src_byte_info", global.GCONFIG_RECORD_ALL_SRC_BYTE_INFO, "启动记录原始请求BODY报文（1启动 0关闭）", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "record_log_desensitize", global.GCONFIG_RECORD_LOG_DESENSITIZE, "请求记录是否进行脱敏处理（1开启脱敏 0关闭脱敏）", "options", "0|关闭脱敏,1|开启脱敏", configMap)
	updateConfigIntItem(initLoad, "system", "token_expire_time", global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES, "管理平台令牌有效期，单位分钟（默认5分钟）", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "spider_deny", global.GCONFIG_RECORD_SPIDER_DENY, "爬虫禁止访问开关 默认 0 只检测不阻止访问 1 检测并阻止访问）", "int", "", configMap)
	updateConfigIntItem(initLoad, "debug", "enable_debug", global.GCONFIG_RECORD_DEBUG_ENABLE, "调试开关 默认关闭", "int", "", configMap)
	updateConfigStringItem(initLoad, "debug", "debug_pwd", global.GCONFIG_RECORD_DEBUG_PWD, "调试密码 如果未空则不需要密码", "string", "", configMap)

	updateConfigStringItem(initLoad, "gpt", "gpt_url", global.GCONFIG_RECORD_GPT_URL, "GPT远程地址 默认：DeepSeek ，符合ChatGpt或者使用one-api封装好的接口都可以", "string", "", configMap)
	updateConfigStringItem(initLoad, "gpt", "gpt_token", global.GCONFIG_RECORD_GPT_TOKEN, "GPT远程授权密钥", "string", "", configMap)
	updateConfigStringItem(initLoad, "gpt", "gpt_model", global.GCONFIG_RECORD_GPT_MODEL, "GPT模型名称", "string", "", configMap)
	updateConfigIntItem(initLoad, "security", "hide_server_header", global.GCONFIG_RECORD_HIDE_SERVER_HEADER, "是否隐藏Server响应头(1隐藏 0不隐藏)", "int", "", configMap)
	updateConfigIntItem(initLoad, "security", "force_bind_2fa", global.GCONFIG_RECORD_FORCE_BIND_2FA, "是否强制绑定双因素认证(1强制 0不强制)", "options", "0|不强制,1|强制", configMap)
	updateConfigIntItem(initLoad, "system", "fake_spider_captcha", global.GCONFIG_RECORD_FAKE_SPIDER_CAPTCHA, "伪爬虫进行图形挑战开关 0 放过 1 显示图形验证码", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "enable_proxy_protocol", global.GCONFIG_ENABLE_PROXY_PROTOCOL, "是否启用Proxy Protocol（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "system", "enable_system_stats_push", global.GCONFIG_ENABLE_SYSTEM_STATS_PUSH, "是否启用系统统计数据推送（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)

	// 指纹认证相关配置
	updateConfigIntItem(initLoad, "security", "enable_device_fingerprint", global.GCONFIG_ENABLE_DEVICE_FINGERPRINT, "是否启用设备指纹认证（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "security", "enable_strict_ip_binding", global.GCONFIG_ENABLE_STRICT_IP_BINDING, "是否启用严格IP绑定（1启用 0禁用，启用指纹时建议禁用）", "options", "0|禁用,1|启用", configMap)
	//数据库相关
	updateConfigIntItem(initLoad, "database", "batch_insert", global.GDATA_BATCH_INSERT, "数据库批量插入数量", "int", "", configMap)
	updateConfigIntItem(initLoad, "database", "log_persist_enable", global.GCONFIG_LOG_PERSIST_ENABLED, "是否开启日志持久化（1开启 0关闭）", "options", "0|关闭,1|开启", configMap)
	updateConfigIntItem(initLoad, "database", "ip_tag_db", global.GDATA_IP_TAG_DB, "IP Tag 存放位置 0 是主库  1是读取 stat库", "int", "", configMap)

	// IP失败封禁相关配置
	updateConfigStringItem(initLoad, "security", "ip_failure_status_codes", global.GCONFIG_IP_FAILURE_STATUS_CODES, "失败状态码配置，支持多个用|分隔，也支持正则表达式，例如：401|403|404|444|429|503 或 ^4[0-9]{2}$", "string", "", configMap)
	updateConfigIntItem(initLoad, "security", "ip_failure_ban_enabled", global.GCONFIG_IP_FAILURE_BAN_ENABLED, "是否启用IP失败封禁（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "security", "ip_failure_ban_lock_time", global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME, "IP失败封禁锁定时间（单位：分钟，默认10分钟）", "int", "", configMap)

	// 版本更新相关配置
	updateConfigIntItem(initLoad, "system", "check_beta_version", global.GCONFIG_CHECK_BETA_VERSION, "是否检测beta版本更新（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)

	// ZeroSSL 相关配置
	updateConfigStringItem(initLoad, "ssl", "zerossl_access_key", global.GCONFIG_ZEROSSL_ACCESS_KEY, "zerossl访问key", "string", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "zerossl_eab_kid", global.GCONFIG_ZEROSSL_EAB_KID, "zerossl eab_kid", "string", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "zerossl_eab_hmac_key", global.GCONFIG_ZEROSSL_EAB_HMAC_KEY, "zerossl eab_hmac_key", "string", "", configMap)

	// IP数据库配置
	updateConfigStringItem(initLoad, "ip_database", "ip_v4_source",
		global.GCONFIG_IP_V4_SOURCE, "IPv4数据库来源",
		"options", "ip2region|ip2region,geolite2|GeoLite2", configMap)
	updateConfigStringItem(initLoad, "ip_database", "ip_v6_source",
		global.GCONFIG_IP_V6_SOURCE, "IPv6数据库来源",
		"options", "ip2region|ip2region,geolite2|GeoLite2", configMap)
	updateConfigStringItem(initLoad, "ip_database", "ip_v4_format",
		global.GCONFIG_IP_V4_FORMAT, "IPv4 xdb字段格式",
		"options", "legacy|老版本,opensource|开源版,full|满载版,standard|标准版,compact|精简版", configMap)
	updateConfigStringItem(initLoad, "ip_database", "ip_v6_format",
		global.GCONFIG_IP_V6_FORMAT, "IPv6 xdb字段格式(仅ip2region时有效)",
		"options", "legacy|老版本,opensource|开源版,full|满载版,standard|标准版,compact|精简版", configMap)

	// 日志文件写入相关配置
	updateConfigIntItem(initLoad, "logfile", "log_file_write_enable", global.GCONFIG_LOG_FILE_WRITE_ENABLE, "日志文件写入开关（0关闭 1开启）", "options", "0|关闭,1|开启", configMap)
	updateConfigStringItem(initLoad, "logfile", "log_file_write_path", global.GCONFIG_LOG_FILE_WRITE_PATH, "日志文件输出路径", "string", "", configMap)
	updateConfigStringItem(initLoad, "logfile", "log_file_write_format", global.GCONFIG_LOG_FILE_WRITE_FORMAT, "日志格式（nginx/apache/custom）", "options", "nginx|Nginx Combined,apache|Apache Combined,custom|自定义格式", configMap)
	updateConfigStringItem(initLoad, "logfile", "log_file_write_custom_tpl", global.GCONFIG_LOG_FILE_WRITE_CUSTOM_TPL, "自定义日志格式模板", "string", "", configMap)
	updateConfigIntItem(initLoad, "logfile", "log_file_write_max_size", global.GCONFIG_LOG_FILE_WRITE_MAX_SIZE, "单个日志文件最大大小（MB）", "int", "", configMap)
	updateConfigIntItem(initLoad, "logfile", "log_file_write_max_backups", global.GCONFIG_LOG_FILE_WRITE_MAX_BACKUPS, "保留的历史文件数量", "int", "", configMap)
	updateConfigIntItem(initLoad, "logfile", "log_file_write_max_days", global.GCONFIG_LOG_FILE_WRITE_MAX_DAYS, "保留天数", "int", "", configMap)
	updateConfigIntItem(initLoad, "logfile", "log_file_write_compress", global.GCONFIG_LOG_FILE_WRITE_COMPRESS, "是否压缩历史文件（0关闭 1开启）", "options", "0|关闭,1|开启", configMap)

	// 开放平台配置
	updateConfigIntItem(initLoad, "openplatform", "open_platform_enabled", global.GCONFIG_OPEN_PLATFORM_ENABLED, "开放平台开关（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)

	// 任务日志配置
	updateConfigIntItem(initLoad, "task", "task_log_retain_days", global.GCONFIG_TASK_LOG_RETAIN_DAYS, "任务日志保留天数（默认30天）", "int", "", configMap)
}
