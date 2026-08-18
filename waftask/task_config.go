package waftask

import (
	"SamWaf/common/tasklog"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/iplocation"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/wafenginecore"
	"SamWaf/wafhostguard"
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
	case "proxy_loop_max_hop":
		global.GCONFIG_RECORD_PROXY_LOOP_MAX_HOP = value
		break
	case "login_max_error_time":
		global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME = value
		break
	case "login_limit_mintutes":
		global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES = value
		break
	case "access_enable":
		global.GCONFIG_ACCESS_ENABLE = value
		// 总开关是运行时快照的一部分，改完必须重新发布，否则要等下次配置保存才生效。
		// 这里也是"改错了能自救"的关键路径：管理端把开关拨回 0，最迟一个刷新周期就恢复。
		waf_service.WafAccessConfigServiceApp.PublishConfig()
		break
	case "access_audit_retain_days":
		global.GCONFIG_ACCESS_AUDIT_RETAIN_DAYS = value
		break
	case "enable_owasp":
		global.GCONFIG_RECORD_ENABLE_OWASP = value
		break
	case "ai_enable":
		global.GCONFIG_AI_ENABLE = value
		break
	case "rule_chain_mode":
		if value != 1 {
			value = 0
		}
		global.GCONFIG_RULE_CHAIN_MODE = value
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
	case "ssl_expire_auto_sync_host":
		if value != 0 {
			value = 1
		}
		global.GCONFIG_SSL_EXPIRE_AUTO_SYNC_HOST = value
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
	case "ipprobe_enable":
		if value != 1 {
			wafenginecore.ClearAllIPProbeSamples() //关闭时把已采到的样本一并清掉，不留残留
		}
		global.GCONFIG_IPPROBE_ENABLE = value
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
	case "host_guard_enabled":
		global.GCONFIG_HOST_GUARD_ENABLED = value
		// 开关切换不需要重启进程：0→1 启动日志采集，1→0 停止采集并释放 fd/子进程/系统句柄。
		// 这也是四层自救里的 L1——把开关拨回 0，最迟一个配置刷新周期就不再产生新封禁。
		wafhostguard.Reload()
		break
	case "host_guard_find_time":
		global.GCONFIG_HOST_GUARD_FIND_TIME = value
		break
	case "host_guard_max_retry":
		global.GCONFIG_HOST_GUARD_MAX_RETRY = value
		break
	case "host_guard_offender_reset_day":
		global.GCONFIG_HOST_GUARD_OFFENDER_RESET_DAY = value
		break
	case "host_guard_count_soft_fail":
		global.GCONFIG_HOST_GUARD_COUNT_SOFT_FAIL = value
		break
	case "host_guard_auto_lan":
		global.GCONFIG_HOST_GUARD_AUTO_LAN = value
		wafhostguard.InvalidateWhitelist()
		// 内网段豁免同时是威胁情报误报排除集的来源，开关一变要重新落地。
		// 只在真的变了时做：启动加载(change=0)时排除集本来就会按需构建，
		// 这里再触发一次对账纯属浪费，还可能赶在防火墙引擎就绪之前。
		if change == 1 {
			waf_service.WafThreatIPExcludeServiceApp.NotifySourceChanged()
		}
		break
	case "host_guard_debounce_sec":
		global.GCONFIG_HOST_GUARD_DEBOUNCE_SEC = value
		break
	case "host_guard_max_ban_entries":
		global.GCONFIG_HOST_GUARD_MAX_BAN_ENTRIES = value
		break
	case "host_guard_ban_rate_limit":
		global.GCONFIG_HOST_GUARD_BAN_RATE_LIMIT = value
		break
	case "host_guard_subnet_aggregate":
		global.GCONFIG_HOST_GUARD_SUBNET_AGGREGATE = value
		break
	case "host_guard_subnet_threshold":
		global.GCONFIG_HOST_GUARD_SUBNET_THRESHOLD = value
		break
	case "host_guard_notify":
		global.GCONFIG_HOST_GUARD_NOTIFY = value
		break
	case "host_conn_enabled":
		global.GCONFIG_HOST_CONN_ENABLED = value
		break
	case "host_conn_cache_sec":
		global.GCONFIG_HOST_CONN_CACHE_SEC = value
		break
	case "check_beta_version":
		global.GCONFIG_CHECK_BETA_VERSION = value
		break
	case "http3":
		global.GCONFIG_ENABLE_HTTP3 = value
		if change == 1 {
			// 光改全局变量不会让任何端口去监听 UDP：h3 实例只在 StartProxyServer 里建，
			// 而已在监听的端口(Status==0)会被直接跳过，所以必须显式让引擎重新对齐(issue #916)。
			// 先赋值再投递，避免消费方读到旧值。
			global.NotifyHTTP3ConfigChanged()
		}
	case "record_log_desensitize":
		global.GCONFIG_RECORD_LOG_DESENSITIZE = value
	case "pwd_min_length":
		global.GCONFIG_PWD_MIN_LENGTH = value
	case "pwd_require_upper":
		global.GCONFIG_PWD_REQUIRE_UPPER = value
	case "pwd_require_lower":
		global.GCONFIG_PWD_REQUIRE_LOWER = value
	case "pwd_require_digit":
		global.GCONFIG_PWD_REQUIRE_DIGIT = value
	case "pwd_require_special":
		global.GCONFIG_PWD_REQUIRE_SPECIAL = value
	case "pwd_expire_days":
		global.GCONFIG_PWD_EXPIRE_DAYS = value
	case "pwd_history_count":
		global.GCONFIG_PWD_HISTORY_COUNT = value
	case "pwd_force_change_default":
		global.GCONFIG_PWD_FORCE_CHANGE_DEFAULT = value
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
		if change == 1 {
			// 拥塞算法变了需要重建 QUIC 监听，同样要通知引擎
			global.NotifyHTTP3ConfigChanged()
		}
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
	case "gwaf_manage_proxy_header":
		global.GCONFIG_MANAGE_PROXY_HEADER = value
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
	case "ai_mode":
		switch value {
		case "observe", "block":
			global.GCONFIG_AI_MODE = value
		default:
			zlog.Warn("invalid ai_mode value, fallback to observe", value)
			global.GCONFIG_AI_MODE = "observe"
		}
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
	case "host_guard_mode":
		if value != "block" {
			value = "observe"
		}
		global.GCONFIG_HOST_GUARD_MODE = value
		break
	case "host_guard_whitelist":
		global.GCONFIG_HOST_GUARD_WHITELIST = value
		// 白名单是防误封的主力，改完必须立刻重建，不能等下一个刷新周期
		wafhostguard.InvalidateWhitelist()
		// 同一份白名单也用来把"自己人"从威胁情报里剔出去，改完要重新落地
		if change == 1 {
			waf_service.WafThreatIPExcludeServiceApp.NotifySourceChanged()
		}
		break
	case "host_guard_log_paths":
		global.GCONFIG_HOST_GUARD_LOG_PATHS = value
		// 日志路径变了要换事件源，重启采集
		wafhostguard.Reload()
		break
	case "host_guard_ssh_ports":
		global.GCONFIG_HOST_GUARD_SSH_PORTS = value
		wafhostguard.InvalidatePorts()
		// 端口变了，端口级封禁的规则也要跟着换
		wafhostguard.GetBanExecutor().ApplyPortScope()
		break
	case "host_guard_rdp_ports":
		global.GCONFIG_HOST_GUARD_RDP_PORTS = value
		wafhostguard.InvalidatePorts()
		wafhostguard.GetBanExecutor().ApplyPortScope()
		break
	case "host_guard_port_scope":
		if value != "detected" {
			value = "all"
		}
		global.GCONFIG_HOST_GUARD_PORT_SCOPE = value
		// 封禁范围要立刻重建引用规则，否则要等下次重启才生效
		wafhostguard.GetBanExecutor().ApplyPortScope()
		break
	case "host_guard_exec_mode":
		if value != "ipset" && value != "rule" {
			value = "auto"
		}
		global.GCONFIG_HOST_GUARD_EXEC_MODE = value
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
	updateConfigStringItem(initLoad, "system", "gwaf_manage_proxy_header", global.GCONFIG_MANAGE_PROXY_HEADER, "管理端获取客户端IP头信息（按优先级逗号分隔，如 X-Forwarded-For,X-Real-IP,CF-Connecting-IP），留空则直接取网络IP。安全起见需配合 conf/config.yml 的 security.manage_trusted_proxies：仅当直连来源属可信代理时才采信此头", "string", "", configMap)

	updateConfigIntItem(initLoad, "kafka", "kafka_enable", global.GCONFIG_RECORD_KAFKA_ENABLE, "kafka 是否激活", "int", "", configMap)
	updateConfigStringItem(initLoad, "kafka", "kafka_url", global.GCONFIG_RECORD_KAFKA_URL, "kafka url地址", "string", "", configMap)
	updateConfigStringItem(initLoad, "kafka", "kafka_topic", global.GCONFIG_RECORD_KAFKA_TOPIC, "kafka topic", "string", "", configMap)

	updateConfigIntItem(initLoad, "system", "redirect_https_code", global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE, "80重定向https时候跳转代码", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "enable_https_redirect", global.GCONFIG_ENABLE_HTTPS_REDIRECT, "是否启用HTTPS重定向服务器（0关闭 1开启）", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "proxy_loop_max_hop", global.GCONFIG_RECORD_PROXY_LOOP_MAX_HOP, "反向代理最大跳数，请求经过SamWaf转发累计超过此值判定为环路并拦截（防后端回指WAF造成死循环），默认10，设为0关闭检测", "int", "", configMap)

	updateConfigIntItem(initLoad, "system", "login_max_error_time", global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME, "登录周期里错误最大次数 请大于0 ", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "login_limit_mintutes", global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES, "登录错误记录周期 单位分钟数，默认1分钟", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "enable_owasp", global.GCONFIG_RECORD_ENABLE_OWASP, "启动OWASP数据检测（1启动 0关闭）", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "ipprobe_enable", global.GCONFIG_IPPROBE_ENABLE, "真实IP来源探针（1开启 0关闭，默认关闭）。开启后记录各站点最近到达的请求头(脱敏,仅内存,每站每秒最多1条)，供站点「真实IP来源」处排查CDN送来的是哪个头；排查完建议关闭", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "ai_enable", global.GCONFIG_AI_ENABLE, "启动AI智能检测总开关（1启动 0关闭，需先在AI模型管理上传模型包并在站点开启）", "int", "", configMap)
	updateConfigStringItem(initLoad, "system", "ai_mode", global.GCONFIG_AI_MODE, "AI检测工作模式：observe(仅记录/观察) block(达拦截阈值则拦截)", "options", "observe|仅记录,block|拦截", configMap)
	updateConfigIntItem(initLoad, "system", "rule_chain_mode", global.GCONFIG_RULE_CHAIN_MODE, "自定义规则在检测链中的位置（0默认：排在CC之后；1规则优先：排在黑名单之后、Bot/SQLI/XSS等之前，此时规则的放行动作才能跳过这些检测）", "int", "", configMap)

	updateConfigIntItem(initLoad, "access", "access_enable", global.GCONFIG_ACCESS_ENABLE, "统一访问认证总开关：开启后所有被WAF代理的站点默认都需先登录才能访问（可在站点里单独强制开/关，也可配置免认证路径与IP组）。请先在【统一访问认证-访问账号】里建好账号再开启", "options", "0|关闭,1|开启", configMap)
	updateConfigIntItem(initLoad, "access", "access_audit_retain_days", global.GCONFIG_ACCESS_AUDIT_RETAIN_DAYS, "统一访问认证审计日志保留天数，默认90天", "int", "", configMap)

	updateConfigIntItem(initLoad, "ssl", "enable_http_80", global.GCONFIG_RECORD_ENABLE_HTTP_80, "启动80端口服务（为自动申请证书使用 HTTP文件验证类型需要，DNS验证不需要）", "int", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "sslorder_expire_day", global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY, "自动续期检测小于多少天开始发起自动申请 默认30天", "int", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_ip_cert_ip", global.GCONFIG_RECORD_SSL_IP_CERT_IP, "获取IP证书时的IP地址（为IP证书申请使用，留空则不使用）", "string", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "ssl_ip_expire_day", global.GCONFIG_RECORD_SSL_IP_EXPIRE_DAY, "IP证书自动续期检测小于多少天开始发起自动申请 默认3天", "int", "", configMap)
	updateConfigIntItem(initLoad, "ssl", "ssl_expire_auto_sync_host", global.GCONFIG_SSL_EXPIRE_AUTO_SYNC_HOST, "SSL证书过期检测前是否自动同步已配置的SSL主机到检测列表（1同步 0不同步，默认1；关闭后过期检测只检测列表里已有的域名，手动点【同步主机】仍可用）", "options", "0|不同步,1|同步", configMap)
	updateConfigIntItem(initLoad, "ssl", "sslhttp_check", global.GCONFIG_RECORD_SSLHTTP_CHECK, "证书文件验证：本地挑战文件始终优先使用；本项仅控制【本地无挑战文件】且后端对 .well-known 返回非404/301/302 时是否写告警日志（1告警 0不告警），不影响能否签发", "int", "", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_min_version", global.GCONFIG_RECORD_SSLMinVerson, "SSL最低版本(支持TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3)，修改后重启一下", "options", "TLS 1.0|TLS 1.0,TLS 1.1|TLS 1.1,TLS 1.2|TLS 1.2,TLS 1.3|TLS 1.3", configMap)
	updateConfigStringItem(initLoad, "ssl", "ssl_max_version", global.GCONFIG_RECORD_SSLMaxVerson, "SSL最大版本(支持TLS 1.0,TLS 1.1,TLS 1.2,TLS 1.3)，修改后重启一下", "options", "TLS 1.0|TLS 1.0,TLS 1.1|TLS 1.1,TLS 1.2|TLS 1.2,TLS 1.3|TLS 1.3", configMap)

	updateConfigIntItem(initLoad, "network", "connect_time_out", global.GCONFIG_RECORD_CONNECT_TIME_OUT, "连接超时（默认30s）", "int", "", configMap)
	updateConfigIntItem(initLoad, "network", "keepalive_time_out", global.GCONFIG_RECORD_KEEPALIVE_TIME_OUT, "保持活动超时（默认30s）", "int", "", configMap)
	updateConfigIntItem(initLoad, "network", "http3", global.GCONFIG_ENABLE_HTTP3, "是否启用HTTP/3(QUIC)。生效前提：①站点必须开启SSL（HTTP/3 只跑在 TLS 上，非HTTPS端口不会监听UDP）；②必须在防火墙/安全组放行对应的【UDP】端口（如 443/udp）。开启后立即生效、无需重启；浏览器通过响应头 Alt-Svc 升级到 h3", "options", "0|关闭,1|开启", configMap)
	updateConfigIntItem(initLoad, "network", "http3_bbr", global.GCONFIG_ENABLE_HTTP3_BBR, "HTTP/3 拥塞控制算法：0=NewReno(默认) 1=BBR。仅在已启用 HTTP/3 时有意义，修改后会自动重建 QUIC 监听", "options", "0|NewReno,1|BBR", configMap)

	updateConfigIntItem(initLoad, "system", "record_all_src_byte_info", global.GCONFIG_RECORD_ALL_SRC_BYTE_INFO, "启动记录原始请求BODY报文（1启动 0关闭）", "int", "", configMap)
	updateConfigIntItem(initLoad, "system", "record_log_desensitize", global.GCONFIG_RECORD_LOG_DESENSITIZE, "请求记录是否进行脱敏处理（1开启脱敏 0关闭脱敏）", "options", "0|关闭脱敏,1|开启脱敏", configMap)
	updateConfigIntItem(initLoad, "system", "token_expire_time", global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES, "管理平台令牌有效期，单位分钟（默认5分钟）", "int", "", configMap)

	// 口令复杂度策略
	updateConfigIntItem(initLoad, "password", "pwd_min_length", global.GCONFIG_PWD_MIN_LENGTH, "密码最小长度（默认8）", "int", "", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_require_upper", global.GCONFIG_PWD_REQUIRE_UPPER, "是否要求包含大写字母", "options", "0|不要求,1|要求", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_require_lower", global.GCONFIG_PWD_REQUIRE_LOWER, "是否要求包含小写字母", "options", "0|不要求,1|要求", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_require_digit", global.GCONFIG_PWD_REQUIRE_DIGIT, "是否要求包含数字", "options", "0|不要求,1|要求", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_require_special", global.GCONFIG_PWD_REQUIRE_SPECIAL, "是否要求包含特殊字符", "options", "0|不要求,1|要求", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_expire_days", global.GCONFIG_PWD_EXPIRE_DAYS, "密码有效期天数（0=不限，到期登录时提示强制更换）", "int", "", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_history_count", global.GCONFIG_PWD_HISTORY_COUNT, "历史密码防重用个数（0=不启用）", "int", "", configMap)
	updateConfigIntItem(initLoad, "password", "pwd_force_change_default", global.GCONFIG_PWD_FORCE_CHANGE_DEFAULT, "默认密码/被重置后是否强制改密", "options", "0|否,1|强制", configMap)
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
	updateConfigIntItem(initLoad, "security", "enable_strict_ip_binding", global.GCONFIG_ENABLE_STRICT_IP_BINDING, "是否启用严格IP绑定（1启用 0禁用；启用后令牌绑定登录时的真实IP，IP变化需重新登录；反向代理后请先配置可信代理网段，否则按代理IP判定）", "options", "0|禁用,1|启用", configMap)
	//数据库相关
	updateConfigIntItem(initLoad, "database", "batch_insert", global.GDATA_BATCH_INSERT, "数据库批量插入数量", "int", "", configMap)
	updateConfigIntItem(initLoad, "database", "log_persist_enable", global.GCONFIG_LOG_PERSIST_ENABLED, "是否开启日志持久化（1开启 0关闭）", "options", "0|关闭,1|开启", configMap)
	updateConfigIntItem(initLoad, "database", "ip_tag_db", global.GDATA_IP_TAG_DB, "IP Tag 存放位置 0 是主库  1是读取 stat库", "int", "", configMap)

	// IP失败封禁相关配置
	updateConfigStringItem(initLoad, "security", "ip_failure_status_codes", global.GCONFIG_IP_FAILURE_STATUS_CODES, "失败状态码配置，支持多个用|分隔，也支持正则表达式，例如：401|403|404|444|429|503 或 ^4[0-9]{2}$", "string", "", configMap)
	updateConfigIntItem(initLoad, "security", "ip_failure_ban_enabled", global.GCONFIG_IP_FAILURE_BAN_ENABLED, "是否启用IP失败封禁（1启用 0禁用）", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "security", "ip_failure_ban_lock_time", global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME, "IP失败封禁锁定时间（单位：分钟，默认10分钟）", "int", "", configMap)

	// 主机远程登录爆破防护(SSH/RDP)。封禁时长不在这里配，由「封禁阶梯」表接管(5分→15分→60分→1天→永久)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_enabled", global.GCONFIG_HOST_GUARD_ENABLED, "主机远程登录爆破防护总开关（保护SamWaf所在机器自身的SSH/RDP。启用前请先确认白名单已包含你的管理IP，否则可能把自己锁在门外）", "options", "0|禁用,1|启用", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_mode", global.GCONFIG_HOST_GUARD_MODE, "工作模式：observe=只记录不封禁（建议先跑一周确认无误封），block=达到阈值即调用系统防火墙封禁", "options", "observe|观察模式,block|封禁模式", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_find_time", global.GCONFIG_HOST_GUARD_FIND_TIME, "失败统计窗口（单位：分钟，默认10分钟）", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_max_retry", global.GCONFIG_HOST_GUARD_MAX_RETRY, "统计窗口内失败次数达到该值即触发处置（默认8次）", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_offender_reset_day", global.GCONFIG_HOST_GUARD_OFFENDER_RESET_DAY, "累犯记忆期（单位：天，默认7天）：超过这么久没再犯，下次封禁从第1级重新开始", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_count_soft_fail", global.GCONFIG_HOST_GUARD_COUNT_SOFT_FAIL, "软失败是否计入阈值（preauth断连/用户名枚举/PAM失败行）。前者由端口扫描与健康探针大量产生，后两者会与密码失败行成对出现导致阈值腰斩，默认不计入", "options", "0|不计入,1|计入", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_whitelist", global.GCONFIG_HOST_GUARD_WHITELIST, "永不封禁的IP/网段白名单，逗号分隔，支持单IP/CIDR/通配符/区间（如 1.2.3.4,10.0.0.0/8,192.168.1.*）", "string", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_auto_lan", global.GCONFIG_HOST_GUARD_AUTO_LAN, "是否自动豁免本机所有网卡IP、环回地址与常见内网段（10/8、172.16/12、192.168/16、fc00::/7、100.64/10、169.254/16）", "options", "0|不豁免,1|自动豁免", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_log_paths", global.GCONFIG_HOST_GUARD_LOG_PATHS, "自定义系统认证日志路径（逗号分隔），留空则自动探测 /var/log/secure、/var/log/auth.log，都没有则用 journalctl。容器部署请把宿主机日志只读挂载进来并在此指定路径", "string", "", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_ssh_ports", global.GCONFIG_HOST_GUARD_SSH_PORTS, "SSH实际监听端口（逗号分隔），留空自动发现。注意：爆破检测本身不依赖端口，改过默认端口也能正常工作，此项仅用于端口级封禁与连接看板高亮", "string", "", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_rdp_ports", global.GCONFIG_HOST_GUARD_RDP_PORTS, "RDP实际监听端口（逗号分隔），留空自动发现", "string", "", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_port_scope", global.GCONFIG_HOST_GUARD_PORT_SCOPE, "封禁范围：all=封全端口（更安全），detected=只封SSH/RDP端口（误封时杀伤面更小）", "options", "all|全端口,detected|仅SSH/RDP端口", configMap)
	updateConfigStringItem(initLoad, "hostguard", "host_guard_exec_mode", global.GCONFIG_HOST_GUARD_EXEC_MODE, "封禁执行方式：auto=平台自适应（推荐），ipset=强制走集合，rule=强制逐条防火墙规则（调试用）", "options", "auto|自动,ipset|集合,rule|逐条规则", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_debounce_sec", global.GCONFIG_HOST_GUARD_DEBOUNCE_SEC, "Windows封禁同步去抖窗口（单位：秒，默认5）。Windows无ipset只能全量重建规则，去抖可避免频繁封禁时反复重建；该值也是封禁生效的最大延迟；Linux/macOS走增量不受此影响", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_max_ban_entries", global.GCONFIG_HOST_GUARD_MAX_BAN_ENTRIES, "封禁集合容量上限（默认10000）。超限时优先淘汰剩余时间最短的临时封禁，永久封禁不淘汰", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_ban_rate_limit", global.GCONFIG_HOST_GUARD_BAN_RATE_LIMIT, "每分钟最多新增封禁数（默认200），防止分布式爆破把封禁集合瞬间打满", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_subnet_aggregate", global.GCONFIG_HOST_GUARD_SUBNET_AGGREGATE, "网段聚合封禁：同一/24网段内被封IP数达到阈值时，升级为封禁整个网段。对僵尸网络有效但误伤面大（可能封掉整个机房/运营商段），默认关闭", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_subnet_threshold", global.GCONFIG_HOST_GUARD_SUBNET_THRESHOLD, "网段聚合触发阈值（同一/24内被封IP数，默认10）", "int", "", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_guard_notify", global.GCONFIG_HOST_GUARD_NOTIFY, "触发封禁时是否发送通知（复用「IP封禁」消息类型，可在通知订阅里配置渠道与频控）", "options", "0|不通知,1|通知", configMap)

	// 远程连接看板
	updateConfigIntItem(initLoad, "hostguard", "host_conn_enabled", global.GCONFIG_HOST_CONN_ENABLED, "远程连接看板开关（展示当前连接到本机的所有TCP连接）", "options", "0|禁用,1|启用", configMap)
	updateConfigIntItem(initLoad, "hostguard", "host_conn_cache_sec", global.GCONFIG_HOST_CONN_CACHE_SEC, "连接快照缓存秒数（默认3秒）。Linux下采集需要遍历/proc建立inode到进程的映射，连接数上万时开销明显，建议不低于3秒", "int", "", configMap)

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

	// 安全提示（升级感知）：配了管理端代理头但未设可信代理网段 → 代理头被忽略、客户端IP取网络层IP。
	// 提醒反向代理后的部署在 conf/config.yml 配置 security.manage_trusted_proxies，
	// 以免 IP白名单/登录锁定误按代理IP生效（该项放 config.yml 便于被白名单挡住时改文件+重启自救）。
	if initLoad && global.GCONFIG_MANAGE_PROXY_HEADER != "" && global.GCONFIG_MANAGE_TRUSTED_PROXIES == "" {
		zlog.Warn("管理端已配置代理头(gwaf_manage_proxy_header)但未设可信代理网段：出于安全，代理头将被忽略、按网络层IP识别客户端。若本机在反向代理之后，请在 conf/config.yml 填写 security.manage_trusted_proxies（如 10.0.0.0/8）后重启")
	}
}
