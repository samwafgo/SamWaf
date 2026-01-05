package model

import (
	"SamWaf/model/baseorm"
	"encoding/json"
)

type Hosts struct {
	baseorm.BaseOrm
	Code                 string `json:"code"`                     //唯一码
	Host                 string `json:"host"`                     //域名
	Port                 int    `json:"port"`                     //端口
	Ssl                  int    `json:"ssl"`                      //是否是ssl
	GUARD_STATUS         int    `json:"guard_status"`             //防御状态 1 是开启防御 0 是防御关闭
	REMOTE_SYSTEM        string `json:"remote_system"`            //是宝塔 phpstudy等
	REMOTE_APP           string `json:"remote_app"`               //是什么类型的应用
	Remote_host          string `json:"remote_host"`              //远端域名
	Remote_port          int    `json:"remote_port"`              //远端端口
	Remote_ip            string `json:"remote_ip"`                //远端指定IP
	Certfile             string `json:"certfile"`                 //证书文件
	Keyfile              string `json:"keyfile"`                  //密钥文件
	REMARKS              string `json:"remarks"`                  //备注
	GLOBAL_HOST          int    `json:"global_host"`              //默认全局 1 全局 0非全局
	DEFENSE_JSON         string `json:"defense_json"`             //自身防御 json
	START_STATUS         int    `json:"start_status"`             //启动状态 如果是0 启动  ; 如果是1 不启动
	EXCLUDE_URL_LOG      string `json:"exclude_url_log"`          //排除的url开头的数据 换行隔开
	IsEnableLoadBalance  int    `json:"is_enable_load_balance"`   //是否激活负载  1 激活  非1 没有激活
	LoadBalanceStage     int    `json:"load_balance_stage"`       //负载策略
	UnrestrictedPort     int    `json:"unrestricted_port"`        //不限来源匹配端口 0 限制 1，不限制
	BindSslId            string `json:"bind_ssl_id"`              //绑定SSL的ID
	AutoJumpHTTPS        int    `json:"auto_jump_https"`          //是否自动跳转https  0 不自动 1 强制80跳转https
	BindMoreHost         string `json:"bind_more_host"`           //绑定多域名
	IsTransBackDomain    int    `json:"is_trans_back_domain"`     //是否传递后端域名到后端服务器侧
	BindMorePort         string `json:"bind_more_port"`           //是否绑定多个端口
	IsEnableHttpAuthBase int    `json:"is_enable_http_auth_base"` //是否 HTTPAuthBase  1 激活  非1 没有激活
	HttpAuthBaseType     string `json:"http_auth_base_type"`      //认证类型 authorization(默认Basic Auth) custom(自定义页面)
	HttpAuthPathPrefix   string `json:"http_auth_path_prefix"`    //HTTP认证路径前缀，用于隐藏系统特征，默认为随机生成
	ResponseTimeOut      int    `json:"response_time_out"`        //响应超时时间 默认60秒,为0则无限等待
	HealthyJSON          string `json:"healthy_json"`             //后端健康度检测 json
	InsecureSkipVerify   int    `json:"insecure_skip_verify"`     //是否开启后端https证书有效性验证 默认 0 是校验 1 是不校验
	CaptchaJSON          string `json:"captcha_json"`             //验证码配置 json
	AntiLeechJSON        string `json:"anti_leech_json"`          //防盗链配置 json
	CacheJSON            string `json:"cache_json"`               //缓存配置 json
	StaticSiteJSON       string `json:"static_site_json"`         //静态站点配置 json
	TransportJSON        string `json:"transport_json"`           //传输配置 json
	DefaultEncoding      string `json:"default_encoding"`         //默认编码 utf-8 或者 gbk  auto字符串自动选择
	LogOnlyMode          int    `json:"log_only_mode"`            //仅记录模式 1开启 0关闭
}

type HostsDefense struct {
	DEFENSE_BOT           int `json:"bot"`       //防御-虚假BOT
	DEFENSE_SQLI          int `json:"sqli"`      //防御-Sql注入
	DEFENSE_XSS           int `json:"xss"`       //防御-xss攻击
	DEFENSE_SCAN          int `json:"scan"`      //防御-scan工具扫描
	DEFENSE_RCE           int `json:"rce"`       //防御-scan工具扫描
	DEFENSE_SENSITIVE     int `json:"sensitive"` //敏感词检测
	DEFENSE_DIR_TRAVERSAL int `json:"traversal"` //目录穿越检测
	DEFENSE_OWASP_SET     int `json:"owaspset"`  //OWASP集检测
}

// HealthyConfig 健康度检测
type HealthyConfig struct {
	IsEnableHealthy int    `json:"is_enable_healthy"` // 是否开启健康检查
	FailCount       int    `json:"fail_count"`        // 连续失败次数
	SuccessCount    int    `json:"success_count"`     // 连续成功次数
	ResponseTime    int    `json:"response_time"`     // 响应时间(秒)
	CheckMethod     string `json:"check_method"`      // 检查方法 GET/HEAD
	CheckPath       string `json:"check_path"`        // 检查路径
	ExpectedCodes   string `json:"expected_codes"`    // 预期状态码
	LastErrorReason string `json:"last_error_reason"` // 最后一次错误原因
}

// CaptchaConfig 验证码配置
type CaptchaConfig struct {
	IsEnableCaptcha int    `json:"is_enable_captcha"` // 是否开启验证码 1开启 0关闭
	ExcludeURLs     string `json:"exclude_urls"`      // 排除验证码的URL列表
	ExpireTime      int    `json:"expire_time"`       // 验证通过后的有效期(小时)
	IPMode          string `json:"ip_mode"`           // IP提取模式: "nic" 网卡模式 或 "proxy" 代理模式
	EngineType      string `json:"engine_type"`       // 验证码引擎类型: 传统方式 "traditional",capJS工作量证明 "capJs"
	PathPrefix      string `json:"path_prefix"`       // 验证码路径前缀，用于隐藏系统特征，默认为随机生成
	CapJsConfig     struct {
		ChallengeCount      int `json:"challengeCount,omitempty"`      // Number of challenges to generate (default: 50)
		ChallengeSize       int `json:"challengeSize,omitempty"`       // Size of each challenge in bytes (default: 32)
		ChallengeDifficulty int `json:"challengeDifficulty,omitempty"` // Difficulty level (default: 4)
		ExpiresMs           int `json:"expiresMs,omitempty"`           // Expiration time in milliseconds (default: 600000)
		InfoTitle           struct {
			En string `json:"en,omitempty"` // English title
			Zh string `json:"zh,omitempty"` // Chinese title
		} `json:"infoTitle,omitempty"` // Multi-language info title
		InfoText struct {
			En string `json:"en,omitempty"` // English text
			Zh string `json:"zh,omitempty"` // Chinese text
		} `json:"infoText,omitempty"` // Multi-language info text
	} `json:"cap_js_config"`
}

// ParseCaptchaConfig 解析验证码配置
func ParseCaptchaConfig(captchaJSON string) CaptchaConfig {
	var config CaptchaConfig

	// 设置默认值
	config.IsEnableCaptcha = 0
	config.ExcludeURLs = ""
	config.ExpireTime = 24
	config.IPMode = "nic"             // 默认使用网卡模式
	config.EngineType = "traditional" // 默认使用传统方式

	// 初始化CapJsConfig默认值
	config.CapJsConfig.ChallengeCount = 50     // 默认生成50个挑战
	config.CapJsConfig.ChallengeSize = 32      // 默认每个挑战32字节
	config.CapJsConfig.ChallengeDifficulty = 4 // 默认难度级别4
	config.CapJsConfig.ExpiresMs = 600000      // 默认过期时间600秒(10分钟)

	// 初始化InfoTitle默认值
	config.CapJsConfig.InfoTitle.Zh = "安全验证"
	config.CapJsConfig.InfoTitle.En = "Security Verification"

	// 初始化InfoText默认值
	config.CapJsConfig.InfoText.Zh = "为了确保您的访问安全，请完成以下验证"
	config.CapJsConfig.InfoText.En = "To ensure the security of your access, please complete the following verification"

	// 如果JSON不为空，则解析覆盖默认值
	if captchaJSON != "" {
		err := json.Unmarshal([]byte(captchaJSON), &config)
		if err != nil {
			// 解析失败时使用默认值，可以记录日志
			return config
		}
	}
	return config
}

// AntiLeechConfig 防盗链配置
type AntiLeechConfig struct {
	IsEnableAntiLeech int    `json:"is_enable_anti_leech"` // 是否开启防盗链 1开启 0关闭
	FileTypes         string `json:"file_types"`           // 需要防盗链的文件类型，例如: gif|jpg|jpeg|png|bmp|swf
	ValidReferers     string `json:"valid_referers"`       // 允许的引用来源列表，使用分号(;)分隔
	Action            string `json:"action"`               // 对于非法引用的处理方式: redirect(重定向) 或 block(直接阻止)
	RedirectURL       string `json:"redirect_url"`         // 重定向URL，当Action为redirect时使用
}

// CacheConfig 缓存配置
type CacheConfig struct {
	IsEnableCache   int     `json:"is_enable_cache"`    // 是否开启缓存 1开启 0关闭
	CacheLocation   string  `json:"cache_location"`     // 缓存位置: "memory"内存 或 "file"文件 或 "all"内存和文件
	CacheDir        string  `json:"cache_dir"`          // 缓存目录，当location为file时使用
	MaxFileSizeMB   float64 `json:"max_file_size_mb"`   // 最大缓存文件大小(MB)  0 是不限制
	MaxMemorySizeMB float64 `json:"max_memory_size_mb"` // 最大内存缓存大小(MB)，当location为memory时使用  0 是不限制
}

// StaticSiteConfig 静态站点配置

type StaticSiteConfig struct {
	IsEnableStaticSite  int    `json:"is_enable_static_site"` // 是否开启静态站点 1开启 0关闭
	StaticSitePath      string `json:"static_site_path"`      // 静态站点路径
	StaticSitePrefix    string `json:"static_site_prefix"`    // 静态站点URL前缀，默认为"/"
	SensitivePaths      string `json:"sensitive_paths"`       // 敏感路径列表，逗号分隔
	SensitiveExtensions string `json:"sensitive_extensions"`  // 敏感文件扩展名，逗号分隔
	AllowedExtensions   string `json:"allowed_extensions"`    // 允许的文件扩展名白名单，逗号分隔
	SensitivePatterns   string `json:"sensitive_patterns"`    // 敏感文件名模式（正则表达式），逗号分隔
}

// TransportConfig 传输配置
type TransportConfig struct {
	MaxIdleConns          int `json:"max_idle_conns"`          // 最大空闲连接数
	MaxIdleConnsPerHost   int `json:"max_idle_conns_per_host"` // 每个主机的最大空闲连接数
	MaxConnsPerHost       int `json:"max_conns_per_host"`      // 每个主机的最大连接数
	IdleConnTimeout       int `json:"idle_conn_timeout"`       // 空闲连接超时时间(秒)
	TLSHandshakeTimeout   int `json:"tls_handshake_timeout"`   // TLS握手超时时间(秒)
	ExpectContinueTimeout int `json:"expect_continue_timeout"` // Expect Continue超时时间(秒)
}

// ParseTransportConfig 解析传输配置
func ParseTransportConfig(transportJSON string) TransportConfig {
	var config TransportConfig

	// 设置默认值
	config.MaxIdleConns = 0
	config.MaxIdleConnsPerHost = 0
	config.MaxConnsPerHost = 0
	config.IdleConnTimeout = 0
	config.TLSHandshakeTimeout = 0
	config.ExpectContinueTimeout = 0

	// 如果JSON不为空，则解析覆盖默认值
	if transportJSON != "" {
		err := json.Unmarshal([]byte(transportJSON), &config)
		if err != nil {
			// 解析失败时使用默认值，可以记录日志
			return config
		}
	}
	return config
}

// ParseHostsDefense 解析防御配置
func ParseHostsDefense(defenseJSON string) HostsDefense {
	var defense HostsDefense

	// 设置默认值
	defense.DEFENSE_BOT = 1
	defense.DEFENSE_SQLI = 1
	defense.DEFENSE_XSS = 1
	defense.DEFENSE_SCAN = 1
	defense.DEFENSE_RCE = 1
	defense.DEFENSE_SENSITIVE = 1
	defense.DEFENSE_DIR_TRAVERSAL = 1
	defense.DEFENSE_OWASP_SET = 0

	// 如果JSON不为空，则解析覆盖默认值
	if defenseJSON != "" {
		err := json.Unmarshal([]byte(defenseJSON), &defense)
		if err != nil {
			// 解析失败时使用默认值，可以记录日志
			return defense
		}
	}
	return defense
}
