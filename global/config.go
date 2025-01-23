package global

var (
	/******记录参数配置****************/
	GCONFIG_RECORD_MAX_BODY_LENGTH     int64  = 1024 * 2            //限制记录最大请求的body长度 record_max_req_body_length
	GCONFIG_RECORD_MAX_RES_BODY_LENGTH int64  = 1024 * 4            //限制记录最大响应的body长度 record_max_rep_body_length
	GCONFIG_RECORD_RESP                int64  = 0                   // 是否记录响应记录 record_resp
	GCONFIG_RECORD_PROXY_HEADER        string = ""                  //配置获取IP头信息
	GCONFIG_RECORD_AUTO_LOAD_SSL       int64  = 1                   //是否每天凌晨3点自动加载ssl证书
	GCONFIG_RECORD_KAFKA_ENABLE        int64  = 0                   //kafka 是否激活
	GCONFIG_RECORD_KAFKA_URL           string = "127.0.0.1:9092"    //kafka url地址
	GCONFIG_RECORD_KAFKA_TOPIC         string = "samwaf_logs_topic" //kafka topic
	GCONFIG_RECORD_REDIRECT_HTTPS_CODE int64  = 301                 //80跳转https的方式

	GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME int64 = 3 //登录周期里错误最大次数
	GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES int64 = 1 //登录错误记录周期 单位分钟最小1

	GCONFIG_RECORD_ENABLE_OWASP        int64 = 0  //启动OWASP数据检测
	GCONFIG_RECORD_ENABLE_HTTP_80      int64 = 0  //启动80端口服务（为自动申请证书使用 HTTP文件验证类型，DNS验证不需要）
	GCONFIG_RECORD_SSLOrder_EXPIRE_DAY int64 = 30 // 提前多少天进行自动申请
	GCONFIG_RECORD_CONNECT_TIME_OUT    int64 = 30 // 连接超时 默认30s
	GCONFIG_RECORD_KEEPALIVE_TIME_OUT  int64 = 30 // 保持活动超时 默认30s
	//GCONFIG_RECORD_PATCH_VERSION_CORE  int64 = 20250106 // 核心数据库补丁日期
	//GCONFIG_RECORD_PATCH_VERSION_LOG   int64 = 20250106 // 日志数据库补丁日期
	GCONFIG_RECORD_ALL_SRC_BYTE_INFO int64 = 0 //记录原始信息(默认不开启)
)
