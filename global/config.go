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

	GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES int64 = 5 //令牌有效期 单位分钟

	GCONFIG_RECORD_DNS_BOT_EXPIRE_HOURS    int64  = 24     //DNS bot有效期 单位小时 默认1天
	GCONFIG_RECORD_DNS_NORMAL_EXPIRE_HOURS int64  = 7 * 24 //DNS 正常有效期 单位小时 默认7天
	GCONFIG_RECORD_SPIDER_DENY             int64  = 0      //爬虫禁止访问开关 默认 0 只检测不阻止访问 1 检测并阻止访问
	GCONFIG_RECORD_HIDE_SERVER_HEADER      int64  = 1      // 是否隐藏Server头信息 1隐藏 0不隐藏
	GCONFIG_RECORD_FORCE_BIND_2FA          int64  = 0      // 是否强制绑定双因素认证(1强制 0不强制)
	GCONFIG_RECORD_DEBUG_ENABLE            int64  = 0      //调试开关 默认关闭
	GCONFIG_RECORD_DEBUG_PWD               string = ""     //调试密码 如果未空则不需要密码

	GCONFIG_RECORD_GPT_URL   string = "https://api.deepseek.com" //GPT远程地址 DeepSeek ChatGpt 以及使用one-api封装好的接口
	GCONFIG_RECORD_GPT_TOKEN string = "SamWaf提示请输入密钥"            //GPT远程授权密钥
	GCONFIG_RECORD_GPT_MODEL string = "deepseek-chat"            //GPT 模型名称
)
