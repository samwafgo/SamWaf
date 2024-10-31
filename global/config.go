package global

var (
	/******记录参数配置****************/
	GCONFIG_RECORD_MAX_BODY_LENGTH     int64  = 1024 * 2                    //限制记录最大请求的body长度 record_max_req_body_length
	GCONFIG_RECORD_MAX_RES_BODY_LENGTH int64  = 1024 * 4                    //限制记录最大响应的body长度 record_max_rep_body_length
	GCONFIG_RECORD_RESP                int64  = 0                           // 是否记录响应记录 record_resp
	GCONFIG_RECORD_PROXY_HEADER        string = "X-Forwarded-For,X-Real-IP" //配置获取IP头信息
	GCONFIG_RECORD_AUTO_LOAD_SSL       int64  = 1                           //是否每天凌晨3点自动加载ssl证书
	GCONFIG_RECORD_KAFKA_ENABLE        int64  = 0                           //kafka 是否激活
	GCONFIG_RECORD_KAFKA_URL           string = "127.0.0.1:9092"            //kafka url地址
	GCONFIG_RECORD_KAFKA_TOPIC         string = "samwaf_logs_topic"         //kafka topic
	GCONFIG_RECORD_REDIRECT_HTTPS_CODE int64  = 301                         //80跳转https的方式

	GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME int64 = 3 //登录周期里错误最大次数
	GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES int64 = 1 //登录错误记录周期 单位分钟最小1
)
