package enums

const (
	CACHE_LOGIN_ERROR    = "CACHE_LOGIN_ERROR"     //登录密码错误
	CACHE_OTP_ERROR      = "CACHE_OTP_ERROR"       //二次验证(OTP)错误，按账户名计数，防 TOTP 爆破
	CACHE_NOTICE_PRE     = "CACHE_NOTICE_PRE"      //通知前缀
	CACHE_CCVISITBAN_PRE = "CACHE_CCVISITBAN_PRE_" //CC封禁前缀
	CACHE_TOKEN          = "CACHE_TOKEN"           //鉴权信息
	CACHE_DNS_BOT_IP     = "CACHE_DNS_BOT_IP"      //IP反向域名解析
	CACHE_DNS_NORMAL_IP  = "CACHE_DNS_NORMAL_IP"   //正常IP
	CACHE_CAPTCHA_TRY    = "CACHE_CAPTCHA_TRY"     //验证码临时
	CACHE_CAPTCHA_PASS   = "CACHE_CAPTCHA_PASS"    //通过验证的码
	CACHE_ANNOUNCEMENT   = "CACHE_ANNOUNCEMENT"    //公告数据
	CACHE_WEBFILE        = "CACHE_WEBFILE"
	CACHE_FILE_INFO      = "CACHE_FILE_INFO"       //文件信息
	CACHE_IP_FAILURE_PRE = "CACHE_IP_FAILURE_PRE"  //IP失败记录前缀
	CACHE_REPLAY_NONCE   = "CACHE_REPLAY_NONCE_"   // 防重放 nonce 前缀
	CACHE_TOKEN_BINDFAIL = "CACHE_TOKEN_BINDFAIL_" // 令牌绑定校验(设备指纹/严格IP)连续失败次数，键后缀是令牌

	// —— 统一访问认证(Access 模式) ——
	// 令牌与会话的真相源是数据库，缓存只是热路径加速。
	// 正向缓存 TTL 有 60 秒硬上限(model.AccessDefaultCachePosTTL)，
	// 这同时也是「管理端踢下线」的最坏生效延迟，不要为了性能把它调大。
	CACHE_ACCESS_TOKEN   = "CACHE_ACCESS_TOKEN_"   //子令牌校验通过的正向缓存，键后缀是 token_code(sha256hex)
	CACHE_ACCESS_SESSION = "CACHE_ACCESS_SESSION_" //中心会话校验通过的正向缓存，键后缀是 session_code
	CACHE_ACCESS_BAD     = "CACHE_ACCESS_BAD_"     //无效令牌负向缓存，挡住拿废弃 Cookie 反复打库的请求
	CACHE_ACCESS_FAIL    = "CACHE_ACCESS_FAIL_"    //登录失败计数，IP 与账号名两个维度分别计数
	CACHE_ACCESS_LOCK    = "CACHE_ACCESS_LOCK_"    //失败锁定标记
	CACHE_ACCESS_STAGE   = "CACHE_ACCESS_STAGE_"   //OTP 两步登录的中间态票据
	CACHE_ACCESS_OTPFAIL = "CACHE_ACCESS_OTPFAIL_" //OTP 失败计数，防 TOTP 爆破
	CACHE_ACCESS_AUDIT   = "CACHE_ACCESS_AUDIT_"   //审计节流标记，防止 denied 事件把审计表刷爆
	CACHE_ACCESS_NOTIFY  = "CACHE_ACCESS_NOTIFY_"  //通知节流标记，审计表扛得住高频，用户的钉钉/邮箱扛不住

	// —— 主机远程登录爆破防护(SSH/RDP) ——
	// 失败计数刻意不复用 CACHE_IP_FAILURE_PRE：那个 keyspace 会被自定义规则的
	// MF.GetIPFailureCount(minutes) 读取，把 SSH 失败混进去会静默改变用户已有 WAF 规则的语义
	// (一个只爆破 SSH 的 IP 会让 HTTP 规则误命中)。
	CACHE_HOST_LOGIN_FAIL_PRE   = "CACHE_HOST_LOGIN_FAIL_"   //主机登录失败计数，键后缀是 source:ip
	CACHE_HOST_GUARD_BANNED_PRE = "CACHE_HOST_GUARD_BANNED_" //已封禁去重标记，TTL 取封禁时长，防同一 IP 短时间重复下发
	CACHE_HOST_GUARD_ADMIN_PRE  = "CACHE_HOST_GUARD_ADMIN_"  //活跃管理会话 IP，防误封的最后一道保险
	CACHE_HOST_GUARD_RATE       = "CACHE_HOST_GUARD_RATE"    //每分钟新增封禁数，挡分布式爆破把封禁集合瞬间打满
	CACHE_HOST_CONN_SNAPSHOT    = "CACHE_HOST_CONN_SNAPSHOT" //远程连接快照，Linux 采集要遍历 /proc，必须带 TTL 缓存
)
