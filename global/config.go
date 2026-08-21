package global

var (
	/******记录参数配置****************/
	GCONFIG_LOG_PERSIST_ENABLED         int64  = 1                   //是否将web日志持久化到日志库（默认1 ） 1 持久化入库 0 不入库
	GCONFIG_RECORD_MAX_BODY_LENGTH      int64  = 1024 * 2            //限制记录最大请求的body长度 record_max_req_body_length
	GCONFIG_RECORD_MAX_RES_BODY_LENGTH  int64  = 1024 * 4            //限制记录最大响应的body长度 record_max_rep_body_length
	GCONFIG_RECORD_RESP                 int64  = 0                   // 是否记录响应记录 record_resp
	GCONFIG_RECORD_PROXY_HEADER         string = ""                  //配置获取IP头信息
	GCONFIG_MANAGE_PROXY_HEADER         string = ""                  //管理端获取客户端IP头信息（逗号分隔按优先级），留空则直接取网络层IP；仅当直连来源属可信代理时才采信
	GCONFIG_MANAGE_TRUSTED_PROXIES      string = ""                  //管理端可信代理网段（CIDR/IP，逗号分隔）；仅当直连来源在此网段内才采信上面的代理头，留空=不信任任何代理头
	GCONFIG_MANAGE_CDN_PROVIDER         string = ""                  //管理端引用的CDN厂商码（管理端也挂CDN时）；设置后GetManageClientIP会额外信任该厂商中心库最新回源段，自动跟随更新
	GCONFIG_SSL_EXPORT_ALLOWED_DIRS     string = ""                  //SSL证书导出允许的额外目录（绝对路径，逗号分隔）；只从config.yml读、不进DB/API。内置默认data/ssl_export恒允许，其余目录须运营方在此声明，攻击者/OpenAPI Key改不了
	GCONFIG_RECORD_AUTO_LOAD_SSL        int64  = 1                   //是否每天凌晨3点自动加载ssl证书
	GCONFIG_RECORD_KAFKA_ENABLE         int64  = 0                   //kafka 是否激活
	GCONFIG_RECORD_KAFKA_URL            string = "127.0.0.1:9092"    //kafka url地址
	GCONFIG_RECORD_KAFKA_TOPIC          string = "samwaf_logs_topic" //kafka topic
	GCONFIG_RECORD_REDIRECT_HTTPS_CODE  int64  = 301                 //80跳转https的方式
	GCONFIG_ENABLE_HTTPS_REDIRECT       int64  = 0                   //是否启用HTTPS重定向服务器 0关闭 1开启
	GCONFIG_RECORD_PROXY_LOOP_MAX_HOP   int64  = 10                  //反向代理最大跳数，超过则判定为环路并拦截；0=关闭环路检测 proxy_loop_max_hop
	GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME int64  = 3                   //登录周期里错误最大次数
	GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES int64  = 1                   //登录错误记录周期 单位分钟最小1
	// 真实IP来源诊断探针：默认关闭。开启后才在内存里采样"最近到达的请求头"供管理端排查，
	// 关闭时业务请求路径上只多一次整型比较；样本只存内存、不落库、不外发。
	GCONFIG_IPPROBE_ENABLE int64 = 0 //真实IP来源探针开关 1开启 0关闭

	// 统一访问认证(Access 模式)
	// 开启后，被 WAF 代理的站点默认都要先登录才能访问；站点可用 access_json 的三态单独强制开/关。
	// 默认 0（关闭）—— 存量用户升级后行为完全不变，这一点不能改。
	GCONFIG_ACCESS_ENABLE            int64 = 0  // 统一访问认证总开关 1开启 0关闭
	GCONFIG_ACCESS_AUDIT_RETAIN_DAYS int64 = 90 // 访问认证审计日志保留天数
	// GCONFIG_ACCESS_FORCE_DISABLE 是自救开关，只能从 conf/config.yml 的 security.access_force_disable
	// 或环境变量 SAMWAF_ACCESS_DISABLE 设置，管理端改不了。
	// 存在的意义：用户把管理端也反代进了 WAF 并开启 Access，一旦配错就会把自己彻底锁在外面，
	// 那时管理端已经进不去，只剩「改配置文件 + 重启」这一条路。
	GCONFIG_ACCESS_FORCE_DISABLE bool = false

	//是否进行系统统计数据推送
	GCONFIG_ENABLE_SYSTEM_STATS_PUSH int64 = 1 // 是否启用系统统计数据推送 1启用 0禁用

	// Proxy Protocol 开关（0：关闭；1：开启）
	GCONFIG_ENABLE_PROXY_PROTOCOL int64 = 0

	// 指纹认证相关配置
	GCONFIG_ENABLE_DEVICE_FINGERPRINT int64 = 0 // 是否启用设备指纹认证 1启用 0禁用
	GCONFIG_ENABLE_STRICT_IP_BINDING  int64 = 0 // 是否启用严格IP绑定 1启用 0禁用(默认关：启用后令牌绑定登录时真实IP，IP变化需重登；反代后需先配可信代理网段。避免动态IP/多出口LB场景反复掉线)
	GCONFIG_ENABLE_REPLAY_PROTECT     int64 = 1 // 防重放攻击开关 1启用 0禁用

	// 容器环境是否允许应用内升级。默认 0=拦截：容器里的可执行文件在镜像可写层，
	// 升级只在本次容器生命周期内有效，容器一重建就回退成镜像里的旧版本，
	// 而数据库已被新版本迁移且回不去，会形成"旧程序 + 新库"的静默不一致状态。
	// 确实把二进制挂到卷里的高级用户可置 1 自行放行。
	GCONFIG_ALLOW_CONTAINER_SELFUPDATE int64 = 0

	GCONFIG_RECORD_ENABLE_OWASP int64  = 0               //启动OWASP数据检测
	GCONFIG_OWASP_MODE          string = "DetectionOnly" //OWASP 检测引擎工作模式: On(拦截) / DetectionOnly(观察/仅记录) / Off(关闭)

	GCONFIG_AI_ENABLE int64  = 0         //AI智能检测总开关 1启用 0关闭（需先在AI模型管理上传模型包）
	GCONFIG_AI_MODE   string = "observe" //AI检测工作模式: observe(仅记录/观察) / block(达到拦截阈值则拦截)

	//自定义规则在检测链里的位置 0:默认(排在CC之后) 1:规则优先(排在黑名单之后、Bot/SQLI/XSS等之前)
	//规则优先模式下，规则的放行动作(RF.Allow)才能跳过 Bot/SQLI/XSS/扫描/RCE/目录穿越/CC 这些检测
	GCONFIG_RULE_CHAIN_MODE int64 = 0

	GCONFIG_OWASP_BLOCK_THRESHOLD      int64  = 7  //OWASP 入站 anomaly score 阈值(官方默认 5,我们宽松到 7)
	GCONFIG_RECORD_ENABLE_HTTP_80      int64  = 0  //启动80端口服务（为自动申请证书使用 HTTP文件验证类型，DNS验证不需要）
	GCONFIG_RECORD_SSLOrder_EXPIRE_DAY int64  = 30 // 提前多少天进行自动申请
	GCONFIG_RECORD_SSL_IP_CERT_IP      string = "" // 获取IP证书时的IP地址
	GCONFIG_RECORD_SSL_IP_EXPIRE_DAY   int64  = 3  // IP证书提前多少天进行自动申请
	GCONFIG_RECORD_SSLHTTP_CHECK       int64  = 0  // ssl文件验证：本地无挑战文件且后端对该路径返回非404/301/302时是否写告警 1告警 0不告警
	// 注意：本地有挑战文件时始终优先使用本地文件，与本项无关
	//SSL过期检测任务开始前，是否自动把已配置的SSL主机同步进过期检测列表 1同步(默认) 0不同步
	//关掉之后过期检测只查用户自己在列表里维护的域名，不会再被主机配置自动塞回来（手动点【同步主机】按钮仍然可用）
	GCONFIG_SSL_EXPIRE_AUTO_SYNC_HOST int64  = 1
	GCONFIG_RECORD_SSLMinVerson       string = "TLS 1.2" // ssl最低版本
	GCONFIG_RECORD_SSLMaxVerson       string = "TLS 1.3" // ssl最大版本
	GCONFIG_RECORD_CONNECT_TIME_OUT   int64  = 30        // 连接超时 默认30s
	GCONFIG_RECORD_KEEPALIVE_TIME_OUT int64  = 30        // 保持活动超时 默认30s
	GCONFIG_RECORD_DRAIN_TIMEOUT      int64  = 30        // 升级/停止时连接优雅排空超时(秒) 默认30s，超时仍未排空的连接将被强制关闭
	//GCONFIG_RECORD_PATCH_VERSION_CORE  int64 = 20250106 // 核心数据库补丁日期
	//GCONFIG_RECORD_PATCH_VERSION_LOG   int64 = 20250106 // 日志数据库补丁日期
	GCONFIG_RECORD_ALL_SRC_BYTE_INFO int64 = 0 //记录原始信息(默认不开启)
	GCONFIG_ENABLE_HTTP3             int64 = 0 //配置是否启用http3(默认关闭)
	GCONFIG_ENABLE_HTTP3_BBR         int64 = 0 //配置http3是否用BBR(默认NewReno)
	GCONFIG_RECORD_LOG_DESENSITIZE   int64 = 1 //请求记录是否进行脱敏处理 1开启脱敏 0关闭脱敏

	// 令牌有效期(分钟)：空闲多久未访问即失效，每次通过鉴权的请求都会滑动续期。
	// 默认由 5 分钟调整为 30 分钟：5 分钟同时充当空闲与绝对超时，配合前端无保活轮询，
	// 表现为"页面开着不动 5 分钟必掉线"（issue #930）。30 分钟落在 OWASP 低风险区间与 NIST 800-63B AAL2 内。
	// 配置值填 0 或负数表示"不管控有效期"，由 waftask.normalizeTokenExpireMinutes 归一化为 1 年封顶，
	// 因此本变量在运行期恒为正数，取用方无需再做防御。
	GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES     int64 = 30 //令牌有效期 单位分钟
	GCONFIG_RECORD_ANNOUNCEMENT_EXPIRE_HOURS int64 = 24 //公告有效期 单位小时

	// 口令复杂度策略（国标 GB/T 32917 §7 自身安全：身份鉴别/口令复杂度）
	GCONFIG_PWD_MIN_LENGTH           int64 = 8 //密码最小长度
	GCONFIG_PWD_REQUIRE_UPPER        int64 = 0 //是否要求大写字母 1要求 0不要求
	GCONFIG_PWD_REQUIRE_LOWER        int64 = 0 //是否要求小写字母 1要求 0不要求
	GCONFIG_PWD_REQUIRE_DIGIT        int64 = 1 //是否要求数字 1要求 0不要求
	GCONFIG_PWD_REQUIRE_SPECIAL      int64 = 0 //是否要求特殊字符 1要求 0不要求
	GCONFIG_PWD_EXPIRE_DAYS          int64 = 0 //密码有效期天数（0=不限，到期登录时提示强制更换）
	GCONFIG_PWD_HISTORY_COUNT        int64 = 0 //历史密码防重用个数（0=不启用）
	GCONFIG_PWD_FORCE_CHANGE_DEFAULT int64 = 1 //默认密码/被重置后是否强制改密 1强制 0否

	GCONFIG_RECORD_DNS_BOT_EXPIRE_HOURS    int64  = 24     //DNS bot有效期 单位小时 默认1天
	GCONFIG_RECORD_DNS_NORMAL_EXPIRE_HOURS int64  = 7 * 24 //DNS 正常有效期 单位小时 默认7天
	GCONFIG_RECORD_SPIDER_DENY             int64  = 0      //爬虫禁止访问开关 默认 0 只检测不阻止访问 1 检测并阻止访问
	GCONFIG_RECORD_FAKE_SPIDER_CAPTCHA     int64  = 0      //伪爬虫进行图形挑战开关 0 放过 1 显示图形验证码
	GCONFIG_RECORD_HIDE_SERVER_HEADER      int64  = 1      // 是否隐藏Server头信息 1隐藏 0不隐藏
	GCONFIG_RECORD_FORCE_BIND_2FA          int64  = 0      // 是否强制绑定双因素认证(1强制 0不强制)
	GCONFIG_RECORD_DEBUG_ENABLE            int64  = 0      //调试开关 默认关闭
	GCONFIG_RECORD_DEBUG_PWD               string = ""     //调试密码 如果未空则不需要密码
	GCONFIG_CORS_ALLOW_ORIGINS             string = ""     //CORS 跨域来源白名单(逗号分隔,大小写不敏感)，默认空=不允许任何跨域(同源管理界面不受影响)

	GCONFIG_RECORD_GPT_URL   string = "https://api.deepseek.com" //GPT远程地址 DeepSeek ChatGpt 以及使用one-api封装好的接口
	GCONFIG_RECORD_GPT_TOKEN string = "SamWaf提示请输入密钥"            //GPT远程授权密钥
	GCONFIG_RECORD_GPT_MODEL string = "deepseek-chat"            //GPT 模型名称

	// IP失败封禁相关配置
	GCONFIG_IP_FAILURE_STATUS_CODES  string = "401|403|404|444|429|503" //失败状态码配置，支持多个用|分隔，也支持正则表达式
	GCONFIG_IP_FAILURE_BAN_ENABLED   int64  = 0                         //是否启用IP失败封禁 1启用 0禁用
	GCONFIG_IP_FAILURE_BAN_LOCK_TIME int64  = 10                        //IP失败封禁锁定时间（分钟）默认10分钟

	GCONFIG_CHECK_BETA_VERSION int64 = 1 //是否检测beta版本更新 1启用 0禁用（默认检测最新版本）

	// ZeroSSL 相关配置
	GCONFIG_ZEROSSL_ACCESS_KEY   string = "" // zerossl访问key
	GCONFIG_ZEROSSL_EAB_KID      string = "" // zerossl eab_kid
	GCONFIG_ZEROSSL_EAB_HMAC_KEY string = "" // zerossl eab_hmac_key

	// 开放平台配置
	GCONFIG_OPEN_PLATFORM_ENABLED int64 = 0 // 开放平台开关，默认关闭 有需要的开启 1启用 0禁用

	// 任务日志配置
	GCONFIG_TASK_LOG_RETAIN_DAYS int64 = 30 // 任务日志保留天数（默认 30 天）

	// 日志文件写入配置 (额外输出，不影响SQLite存储)
	GCONFIG_LOG_FILE_WRITE_ENABLE      int64  = 0                 // 日志文件写入开关 (0关闭 1开启)
	GCONFIG_LOG_FILE_WRITE_PATH        string = "logs/access.log" // 日志文件路径
	GCONFIG_LOG_FILE_WRITE_FORMAT      string = "nginx"           // 日志格式: nginx, apache, custom
	GCONFIG_LOG_FILE_WRITE_CUSTOM_TPL  string = ""                // 自定义格式模板
	GCONFIG_LOG_FILE_WRITE_MAX_SIZE    int64  = 100               // 单个日志文件最大大小 (MB)
	GCONFIG_LOG_FILE_WRITE_MAX_BACKUPS int64  = 10                // 保留的历史文件数量
	GCONFIG_LOG_FILE_WRITE_MAX_DAYS    int64  = 30                // 保留天数
	GCONFIG_LOG_FILE_WRITE_COMPRESS    int64  = 0                 // 是否压缩历史文件 (0关闭 1开启)

	// 主机远程登录爆破防护(SSH/RDP)
	// 保护的是 SamWaf 所在这台机器自身，与 WAF 引擎(保护 Web 站点)是两件事。
	// 默认关闭且默认观察模式 —— 这类功能一旦误封就是"自己 SSH 进不去"，不能开箱即封。
	GCONFIG_HOST_GUARD_ENABLED            int64  = 0         // 主机防爆破总开关 1启用 0禁用
	GCONFIG_HOST_GUARD_MODE               string = "observe" // 工作模式 observe(只记录不封禁) / block(达阈值即封)
	GCONFIG_HOST_GUARD_FIND_TIME          int64  = 10        // 失败统计窗口(分钟)
	GCONFIG_HOST_GUARD_MAX_RETRY          int64  = 8         // 窗口内失败达该次数触发处置
	GCONFIG_HOST_GUARD_OFFENDER_RESET_DAY int64  = 7         // 累犯记忆期(天)，超过则下次封禁从第1级重新开始
	GCONFIG_HOST_GUARD_COUNT_SOFT_FAIL    int64  = 0         // 软失败(preauth断连/用户名枚举/PAM行)是否计入阈值 1计入 0不计入
	GCONFIG_HOST_GUARD_WHITELIST          string = ""        // 永不封禁的IP/网段，逗号分隔，支持单IP/CIDR/通配符/区间
	GCONFIG_HOST_GUARD_AUTO_LAN           int64  = 1         // 是否自动豁免本机网卡IP、环回与常见内网段 1豁免 0不豁免
	GCONFIG_HOST_GUARD_LOG_PATHS          string = ""        // 自定义认证日志路径(逗号分隔)，留空自动探测；容器部署的逃生口
	GCONFIG_HOST_GUARD_SSH_PORTS          string = ""        // SSH实际端口(逗号分隔)，留空自动发现
	GCONFIG_HOST_GUARD_RDP_PORTS          string = ""        // RDP实际端口(逗号分隔)，留空自动发现
	GCONFIG_HOST_GUARD_PORT_SCOPE         string = "all"     // 封禁范围 all(全端口，更安全) / detected(只封SSH/RDP端口)
	GCONFIG_HOST_GUARD_EXEC_MODE          string = "auto"    // 执行方式 auto(平台自适应) / ipset(强制集合) / rule(强制逐条规则)
	// Windows 去抖合并窗口(秒)，Linux/macOS 走增量不受影响。
	// 取 5 而不是 30：去抖的目的是把"一阵爆发"合并成一次重建，5 秒已经足够
	// 收拢成百上千条封禁；再往上加只是让"通知都收到了、防火墙里还没这个 IP"
	// 的观感变差，换不来多少重建次数的下降。
	GCONFIG_HOST_GUARD_DEBOUNCE_SEC     int64 = 5
	GCONFIG_HOST_GUARD_MAX_BAN_ENTRIES  int64 = 10000 // 封禁集合容量上限，超限先淘汰剩余时间最短的临时封禁(永久封不淘汰)
	GCONFIG_HOST_GUARD_BAN_RATE_LIMIT   int64 = 200   // 每分钟最多新增封禁数，防分布式爆破把集合瞬间打满
	GCONFIG_HOST_GUARD_SUBNET_AGGREGATE int64 = 0     // 网段聚合开关，同/24内被封数达阈值则升级封整段。误伤面大，默认关
	GCONFIG_HOST_GUARD_SUBNET_THRESHOLD int64 = 10    // 网段聚合触发阈值
	GCONFIG_HOST_GUARD_NOTIFY           int64 = 1     // 触发封禁时是否发通知(复用「IP封禁」消息类型)
	// GCONFIG_HOST_GUARD_FORCE_DISABLE 是自救开关，只能从 conf/config.yml 的
	// security.host_guard_force_disable 或环境变量 SAMWAF_HOSTGUARD_DISABLE 设置，管理端改不了。
	// 存在的意义：白名单配错把自己的管理IP也封进 iptables 后，SSH 和管理端会同时进不去，
	// 那时只剩物理控制台/云厂商VNC，能操作的只有配置文件。
	GCONFIG_HOST_GUARD_FORCE_DISABLE bool = false

	// 远程连接看板
	GCONFIG_HOST_CONN_ENABLED   int64 = 1 // 连接看板开关 1启用 0禁用
	GCONFIG_HOST_CONN_CACHE_SEC int64 = 3 // 连接快照缓存秒数(Linux采集需遍历/proc，建议不低于3)
)
