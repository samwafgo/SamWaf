package model

import (
	"SamWaf/model/baseorm"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Hosts struct {
	baseorm.BaseOrm
	Code                      string `gorm:"size:64" json:"code"`                           //唯一码
	Host                      string `gorm:"size:255" json:"host"`                          //域名
	Port                      int    `json:"port"`                                          //端口
	Ssl                       int    `json:"ssl"`                                           //是否是ssl
	GUARD_STATUS              int    `json:"guard_status"`                                  //防御状态 1 是开启防御 0 是防御关闭
	REMOTE_SYSTEM             string `gorm:"size:50" json:"remote_system"`                  //是宝塔 phpstudy等
	REMOTE_APP                string `gorm:"size:100" json:"remote_app"`                    //是什么类型的应用
	Remote_host               string `gorm:"size:255" json:"remote_host"`                   //远端域名
	Remote_port               int    `json:"remote_port"`                                   //远端端口
	Remote_ip                 string `gorm:"size:64" json:"remote_ip"`                      //远端指定IP
	Certfile                  string `gorm:"type:text" json:"certfile"`                     //证书文件
	Keyfile                   string `gorm:"type:text" json:"keyfile"`                      //密钥文件
	Nickname                  string `gorm:"size:200" json:"nickname"`                      //网站昵称
	REMARKS                   string `gorm:"size:500" json:"remarks"`                       //备注
	GLOBAL_HOST               int    `json:"global_host"`                                   //默认全局 1 全局 0非全局
	DEFENSE_JSON              string `gorm:"type:text" json:"defense_json"`                 //自身防御 json
	START_STATUS              int    `json:"start_status"`                                  //启动状态 如果是0 启动  ; 如果是1 不启动
	EXCLUDE_URL_LOG           string `gorm:"type:text" json:"exclude_url_log"`              //排除的url开头的数据 换行隔开
	IsEnableLoadBalance       int    `json:"is_enable_load_balance"`                        //是否激活负载  1 激活  非1 没有激活
	LoadBalanceStage          int    `json:"load_balance_stage"`                            //负载策略
	UnrestrictedPort          int    `json:"unrestricted_port"`                             //不限来源匹配端口 0 限制 1，不限制
	BindSslId                 string `gorm:"size:64" json:"bind_ssl_id"`                    //绑定SSL的ID
	AutoJumpHTTPS             int    `json:"auto_jump_https"`                               //是否自动跳转https  0 不自动 1 强制80跳转https
	BindMoreHost              string `gorm:"type:text" json:"bind_more_host"`               //绑定多域名
	IsTransBackDomain         int    `json:"is_trans_back_domain"`                          //是否传递后端域名到后端服务器侧
	BindMorePort              string `gorm:"size:255" json:"bind_more_port"`                //是否绑定多个端口
	IsEnableHttpAuthBase      int    `json:"is_enable_http_auth_base"`                      //是否 HTTPAuthBase  1 激活  非1 没有激活
	HttpAuthBaseType          string `gorm:"size:50" json:"http_auth_base_type"`            //认证类型 authorization(默认Basic Auth) custom(自定义页面)
	HttpAuthPathPrefix        string `gorm:"size:255" json:"http_auth_path_prefix"`         //HTTP认证路径前缀，用于隐藏系统特征，默认为随机生成
	HttpAuthJSON              string `gorm:"type:text" json:"http_auth_json"`               //网站密码访问的会话时效配置 json（有效期/空闲超时/绑定登录IP），空=按 DecodeHttpAuthConfig 的默认值
	ResponseTimeOut           int    `json:"response_time_out"`                             //响应超时时间 默认60秒,为0则无限等待
	HealthyJSON               string `gorm:"type:text" json:"healthy_json"`                 //后端健康度检测 json
	InsecureSkipVerify        int    `json:"insecure_skip_verify"`                          //是否开启后端https证书有效性验证 默认 0 是校验 1 是不校验
	CaptchaJSON               string `gorm:"type:text" json:"captcha_json"`                 //验证码配置 json
	AntiLeechJSON             string `gorm:"type:text" json:"anti_leech_json"`              //防盗链配置 json
	CacheJSON                 string `gorm:"type:text" json:"cache_json"`                   //缓存配置 json
	StaticSiteJSON            string `gorm:"type:text" json:"static_site_json"`             //静态站点配置 json
	TransportJSON             string `gorm:"type:text" json:"transport_json"`               //传输配置 json
	DefaultEncoding           string `gorm:"size:20" json:"default_encoding"`               //默认编码 utf-8 或者 gbk  auto字符串自动选择
	LogOnlyMode               int    `json:"log_only_mode"`                                 //仅记录模式 1开启 0关闭
	CustomHeadersJSON         string `gorm:"type:text" json:"custom_headers_json"`          //自定义头信息配置 json
	CustomResponseHeadersJSON string `gorm:"type:text" json:"custom_response_headers_json"` //自定义响应头信息配置 json
	ResponseCompressJSON      string `gorm:"type:text" json:"response_compress_json"`       //响应压缩配置 json（Gzip/Brotli/Zstd）
	CookieSecurityJSON        string `gorm:"type:text" json:"cookie_security_json"`         //Cookie安全保护配置 json（HttpOnly/Secure/SameSite）
	CsrfJSON                  string `gorm:"type:text" json:"csrf_json"`                    //CSRF防护配置 json（Origin/Referer 强校验）
	TamperJSON                string `gorm:"type:text" json:"tamper_json"`                  //网页防篡改配置 json（响应基线比对）
	UploadSecurityJSON        string `gorm:"type:text" json:"upload_security_json"`         //文件上传内容检测配置 json（扩展名/Webshell/类型/大小）
	IPMode                    string `gorm:"size:20" json:"ip_mode"`                        //IP提取模式: "nic" 网卡模式 或 "proxy" 代理模式
	DisableHTTP2              int    `json:"disable_http2"`                                 //对外HTTP/2开关 0启用(默认/现状) 1关闭(该站点ALPN只提供http/1.1,兼容安卓等原生WebSocket客户端)
	IsEnableResponseBuffering int    `json:"is_enable_response_buffering"`                  //响应缓冲 1开启(默认) 0关闭(类似 nginx proxy_buffering off，边收边推，利于流式/SSE/大文件)
	// 真实客户端 IP 提取加固（向后兼容：IPSourceMode 为空时行为与旧版完全一致——取 X-Forwarded-For 最左第一个）
	IPSourceMode   string `gorm:"size:20" json:"ip_source_mode"`     //真实IP来源模式: ""(兼容,取最左) | nic | header | xff_depth | cdn_preset
	IPTrustDepth   int    `json:"ip_trust_depth"`                    //xff_depth 模式：从右往左取第 N 个非可信 hop(默认1)
	IPRealHeader   string `gorm:"size:64" json:"ip_real_header"`     //header/cdn_preset 模式指定的真实IP头，如 CF-Connecting-IP
	IPTrustProxies string `gorm:"type:text" json:"ip_trust_proxies"` //可信代理网段(CIDR/IP，逗号分隔)，用于 xff_depth 跳过可信 hop
	CDNProvider    string `gorm:"size:32" json:"cdn_provider"`       //cdn_preset 模式选择的 CDN 厂商: cloudflare|fastly|cloudfront|edgeone|aliyun|akamai
	AccessJSON     string `gorm:"type:text" json:"access_json"`      //统一访问认证(Access模式)站点级配置 json（三态开关/路径白名单）
	// GroupCode 所属分组短码，空=未分组。
	// 纯管理端组织维度：只用于列表筛选与批量选择，不参与任何请求期判定，也不下发引擎（见 model/host_group.go）。
	GroupCode string `gorm:"size:64" json:"group_code"`
	// PortListensJSON 端口监听表(JSON)，形如 [{"port":80,"proto":"http","ipv":"both"}]。
	// 空 = 按老规则从 Ssl/BindMorePort/AutoJumpHTTPS 派生（存量站点保持原行为）。
	// addr 为预留字段：当前版本不生效，引擎读到会忽略并按通配监听。
	// 解析唯一入口 utils.ResolveHostListens，其它地方不得自行解析。
	PortListensJSON string `gorm:"size:2048" json:"port_listens_json"`
	// EmergencyMode 紧急模式（对标 Under Attack Mode）：1=开启，全部页面请求先过一次人机验证。
	//
	// 它是站点级总闸，不改动任何一条 CC 规则——把规则的动作改掉再改回来，
	// 中间出任何岔子都恢复不回原样，而这个开关多半是在被打的时候按的。
	// 「永不挑战的路径」对它同样生效：App/API 客户端跑不了 JS 挑战，必须留得出口。
	EmergencyMode int `json:"emergency_mode"`
	// EmergencyUntil 紧急模式自动关闭时间(unix 秒)，0=手动关闭前一直开着。
	// 默认给一个到期时间：这个开关会让全部访客多走一道挑战，忘了关的代价由真实用户承担。
	EmergencyUntil int64 `json:"emergency_until"`
}

// DisplayName 站点在下拉/清单里的显示名：域名:端口(昵称,SSL,备注)。
// 同一个域名常常有多条记录（不同端口各一条），只显示域名会看起来像重复数据。
// 各处统一走这里，避免两个地方各写一份、显示名对不上。
func (h Hosts) DisplayName() string {
	var bracketContent []string
	if h.Nickname != "" {
		bracketContent = append(bracketContent, h.Nickname)
	}
	if h.Ssl == 1 {
		bracketContent = append(bracketContent, "SSL")
	}
	if h.REMARKS != "" {
		bracketContent = append(bracketContent, h.REMARKS)
	}
	if len(bracketContent) > 0 {
		return fmt.Sprintf("%s:%d(%s)", h.Host, h.Port, strings.Join(bracketContent, ","))
	}
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// IsEmergencyActive 紧急模式当前是否生效（已开启且未到自动关闭时间）。
// 到期判定放在读取侧而不是靠定时任务改库：定时任务没跑到的那段时间里，
// 库里写着「开」而实际早该关了，两者不一致比晚关几秒更难查。
func (h *Hosts) IsEmergencyActive(nowUnix int64) bool {
	if h == nil || h.EmergencyMode != 1 {
		return false
	}
	return h.EmergencyUntil <= 0 || h.EmergencyUntil > nowUnix
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
	DEFENSE_AI            int `json:"ai"`        //AI智能检测（默认关闭，需先上传模型包并开启全局AI开关）
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

// FlexInt 兼容 JSON 里被写成字符串的数字（如 "24"）。
//
// 存量 captcha_json 里的数值字段大多是字符串形式。用普通 int 接收时，
// encoding/json 会跳过该字段、继续解析其余字段，并只在最后返回一个类型错误——
// 结果是字段悄悄回落到默认值：用户改了不生效，界面上也没有任何提示。
type FlexInt int

func (f *FlexInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		str = strings.TrimSpace(str)
		if str == "" {
			return nil
		}
		n, err := strconv.Atoi(str)
		if err != nil {
			return err
		}
		*f = FlexInt(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = FlexInt(n)
	return nil
}

// FlexLines 兼容 JSON 里被写成数组的换行分隔清单（如 ["/a","/b"]）。
//
// 存量 captcha_json 的 exclude_urls 有字符串和数组两种写法。用普通 string 接收数组时，
// encoding/json 同样是跳过该字段、继续解析其余字段——清单会整份消失，
// 表现为「明明配了永不挑战的路径，却照样被挑战」。
type FlexLines string

func (f *FlexLines) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" || s == "null" {
		return nil
	}
	if s[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		lines := make([]string, 0, len(arr))
		for _, v := range arr {
			if v = strings.TrimSpace(v); v != "" {
				lines = append(lines, v)
			}
		}
		*f = FlexLines(strings.Join(lines, "\n"))
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*f = FlexLines(str)
	return nil
}

// CaptchaConfig 验证码配置
type CaptchaConfig struct {
	IsEnableCaptcha FlexInt   `json:"is_enable_captcha"` // 是否开启验证码 1开启 0关闭
	ExcludeURLs     FlexLines `json:"exclude_urls"`      // 排除验证码的URL列表（换行分隔；对所有触发来源生效）
	ExpireTime      FlexInt   `json:"expire_time"`       // 验证通过后的有效期(小时)
	IPMode          string    `json:"ip_mode"`           // IP提取模式: "nic" 网卡模式 或 "proxy" 代理模式
	EngineType      string    `json:"engine_type"`       // 验证码引擎类型: 传统方式 "traditional",capJS工作量证明 "capJs"
	PathPrefix      string    `json:"path_prefix"`       // 验证码路径前缀，用于隐藏系统特征，默认为随机生成
	// ContactInfo 管理员联系方式，填了就显示在挑战页上，留空则整块不渲染。
	//
	// 挑战页对访客是个死胡同：被挡住之后既进不去、也没地方问。这一栏就是给这种情况留的出口。
	// 内容由管理员自己写（邮箱、电话、工单地址、一句说明都行），渲染时**必须 HTML 转义**——
	// 它出现在给访客看的公开页面上。
	ContactInfo string `json:"contact_info"` // 挑战页展示的管理员联系方式，留空=不显示
	CapJsConfig struct {
		ChallengeCount      FlexInt `json:"challengeCount,omitempty"`      // Number of challenges to generate (default: 50)
		ChallengeSize       FlexInt `json:"challengeSize,omitempty"`       // Size of each challenge in bytes (default: 32)
		ChallengeDifficulty FlexInt `json:"challengeDifficulty,omitempty"` // Difficulty level (default: 4)
		ExpiresMs           FlexInt `json:"expiresMs,omitempty"`           // Expiration time in milliseconds (default: 600000)
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
	// 归一化验证方式：只认 traditional / capJs，其余一律按 traditional。
	//
	// 存量数据里出现过 "default" 这种当前代码不认的值（更早版本或导入留下的）。
	// 下游按 EngineType 分发挑战页时是「两个 if，没有 else」，
	// 取到不认识的值就两个分支都不进、什么都不写——响应是空的、挑战永远发不出来，
	// 而配置、日志、界面上一切正常。在解析入口收口，所有下游一次性受益。
	if config.EngineType != CaptchaEngineTraditional && config.EngineType != CaptchaEngineCapJs {
		config.EngineType = CaptchaEngineTraditional
	}
	// 联系方式要显示在公开的挑战页上，在解析入口就把长度封住：
	// 这段文本来自管理端输入，界面上限制得住，直接改库或旧数据限制不住。
	config.ContactInfo = strings.TrimSpace(config.ContactInfo)
	if n := []rune(config.ContactInfo); len(n) > CaptchaContactMaxRunes {
		config.ContactInfo = string(n[:CaptchaContactMaxRunes])
	}
	return config
}

// 验证方式取值。只有这两个是引擎认得的，其余一律按 traditional 处理（见 ParseCaptchaConfig）。
const (
	CaptchaEngineTraditional = "traditional"
	CaptchaEngineCapJs       = "capJs"
)

// CaptchaContactMaxRunes 挑战页联系方式的长度上限（按字符算，不是字节）。
// 够写下"邮箱 + 电话 + 一句说明"，又不至于让人把整页说明塞进挑战页。
const CaptchaContactMaxRunes = 200

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

// StaticSecurityHeader 静态站点安全响应头项
type StaticSecurityHeader struct {
	HeaderName  string `json:"header_name"`  // 响应头名称
	HeaderValue string `json:"header_value"` // 响应头值，留空则使用系统默认值
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
	// 安全响应头列表，数组为空则全部使用系统默认值；
	// 某项 header_value 为空则该项也使用系统默认值
	SecurityHeaders []StaticSecurityHeader `json:"security_headers"`
	SpaFallback     int                    `json:"-"` // 运行时标志：由路径规则注入，不写入 host JSON
}

// ResponseCompressConfig 反代响应压缩（类似 nginx gzip / brotli / zstd）
type ResponseCompressConfig struct {
	IsEnable                 int    `json:"is_enable"`                   // 1 开启 0 关闭
	Prefer                   string `json:"prefer"`                      // br_first | gzip_only | br_only | zstd_only
	MinLength                int    `json:"min_length"`                  // 最小压缩字节数，0 表示用默认
	IncludeTypes             string `json:"include_types"`               // 分号分隔 MIME 前缀或完整类型，空则用内置默认
	IncludeExtensions        string `json:"include_extensions"`          // 分号分隔，如 .js;.css，与类型取并集
	ExcludeExtensions        string `json:"exclude_extensions"`          // 分号或换行分隔后缀
	ExcludePaths             string `json:"exclude_paths"`               // 换行或分号，URL 前缀匹配
	CompressWhenStaticAssist int    `json:"compress_when_static_assist"` // 1 时对静态协助响应也读体压缩
}

// CookieSecurityConfig Cookie 安全保护（应答方向给后端下发的 Set-Cookie 补齐安全属性）
// 设计原则：缺失才补——仅在对应属性缺失时追加，绝不覆盖应用已设的值，保留原 cookie 全部内容。
type CookieSecurityConfig struct {
	IsEnable       int    `json:"is_enable"`       // 1 开启 0 关闭（默认0，老站点不受影响）
	HttpOnly       int    `json:"http_only"`       // 1 缺失时补 HttpOnly / 0 不动（默认1）
	Secure         int    `json:"secure"`          // 0 不动 / 1 强制补 / 2 仅 HTTPS 自动补（默认2）
	SameSite       string `json:"same_site"`       // "" 不动 / Lax / Strict / None（默认Lax）
	ExcludeCookies string `json:"exclude_cookies"` // 排除的 cookie 名，逗号分隔（如三方/SSO cookie 原样放过）
}

// ParseCookieSecurityConfig 解析 Cookie 安全保护配置；空 JSON 给安全默认值（但默认关闭）
func ParseCookieSecurityConfig(jsonStr string) CookieSecurityConfig {
	c := CookieSecurityConfig{
		IsEnable: 0,
		HttpOnly: 1,
		Secure:   2,
		SameSite: "Lax",
	}
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return CookieSecurityConfig{IsEnable: 0, HttpOnly: 1, Secure: 2, SameSite: "Lax"}
	}
	return c
}

// CsrfConfig CSRF 跨站请求伪造防护配置（Origin/Referer 强校验）
type CsrfConfig struct {
	IsEnable       int    `json:"is_enable"`       // 1 开启 0 关闭（默认0，老站点不受影响）
	ProtectMethods string `json:"protect_methods"` // 需保护的方法，逗号分隔（默认 "POST,PUT,DELETE,PATCH"；GET/HEAD/OPTIONS 等安全方法不校验）
	AllowedOrigins string `json:"allowed_origins"` // 额外允许的来源(host 或 scheme://host)，换行分隔；本站域名 + BindMoreHost 自动允许
	AllowEmptyRef  int    `json:"allow_empty_ref"` // 无 Origin 且无 Referer 时：1 放行(默认) / 0 拦截
	ExcludePaths   string `json:"exclude_paths"`   // 排除的路径前缀，换行分隔（webhook/回调/Token鉴权API）
}

// ParseCsrfConfig 解析 CSRF 防护配置；空 JSON 给安全默认值（但默认关闭）
func ParseCsrfConfig(jsonStr string) CsrfConfig {
	c := CsrfConfig{
		IsEnable:       0,
		ProtectMethods: "POST,PUT,DELETE,PATCH",
		AllowEmptyRef:  1,
	}
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return CsrfConfig{IsEnable: 0, ProtectMethods: "POST,PUT,DELETE,PATCH", AllowEmptyRef: 1}
	}
	if c.ProtectMethods == "" {
		c.ProtectMethods = "POST,PUT,DELETE,PATCH"
	}
	return c
}

// TamperConfig 网页防篡改配置（反代响应基线比对）
type TamperConfig struct {
	IsEnable  int    `json:"is_enable"`   // 1 开启 0 关闭（默认0，老站点不受影响）
	Action    string `json:"action"`      // "replace"(比对+命中回吐正确副本+告警,默认) / "alert"(仅告警,仍放行后端页,监控档)
	MaxSizeKB int    `json:"max_size_kb"` // 基线最大字节(KB)，默认1024(1MB)，超限不学习/不保护
}

// ParseTamperConfig 解析网页防篡改配置；空 JSON 给安全默认值（但默认关闭）
func ParseTamperConfig(jsonStr string) TamperConfig {
	c := TamperConfig{
		IsEnable:  0,
		Action:    "replace",
		MaxSizeKB: 1024,
	}
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return TamperConfig{IsEnable: 0, Action: "replace", MaxSizeKB: 1024}
	}
	if c.Action == "" {
		c.Action = "replace"
	}
	if c.MaxSizeKB <= 0 {
		c.MaxSizeKB = 1024
	}
	return c
}

// UploadSecurityConfig 文件上传内容检测配置（multipart 上传的扩展名/Webshell/类型/大小四维检测）
type UploadSecurityConfig struct {
	IsEnable        int    `json:"is_enable"`         // 1 开启 0 关闭（默认0，老站点不受影响）
	CheckExt        int    `json:"check_ext"`         // 1 启用扩展名黑名单检测
	ExtBlacklist    string `json:"ext_blacklist"`     // 危险扩展名黑名单，逗号分隔；空用默认
	CheckContent    int    `json:"check_content"`     // 1 启用 Webshell 内容特征检测
	CheckMagic      int    `json:"check_magic"`       // 1 启用“声明类型与真实内容不符”检测
	CheckSize       int    `json:"check_size"`        // 1 启用单文件大小上限检测
	MaxSizeKB       int    `json:"max_size_kb"`       // 单文件大小上限KB=检测缓冲上限，默认10240(10MB)
	OverLimitAction string `json:"over_limit_action"` // 请求体超过检测上限时：block(默认,fail-closed防绕过)/pass(放行不检测)
	IncludePaths    string `json:"include_paths"`     // 只检测这些路径前缀，换行分隔；空=所有路径
	ExcludePaths    string `json:"exclude_paths"`     // 跳过这些路径前缀，换行分隔；优先于 include
}

// DefaultUploadExtBlacklist 默认危险扩展名黑名单
const DefaultUploadExtBlacklist = "php,php2,php3,php4,php5,php7,pht,phtml,phar,jsp,jspx,jspa,jsw,jsv,jspf,asp,aspx,asa,asax,ascx,ashx,asmx,cer,cdx,exe,dll,sh,bat,cmd,com,cgi,pl,py,jar,war"

// ParseUploadSecurityConfig 解析文件上传检测配置；空 JSON 给默认值（默认关闭、超限拦、10MB）
func ParseUploadSecurityConfig(jsonStr string) UploadSecurityConfig {
	c := UploadSecurityConfig{
		IsEnable:        0,
		OverLimitAction: "block",
		MaxSizeKB:       10240,
	}
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return UploadSecurityConfig{IsEnable: 0, OverLimitAction: "block", MaxSizeKB: 10240}
	}
	if c.OverLimitAction == "" {
		c.OverLimitAction = "block"
	}
	if c.MaxSizeKB <= 0 {
		c.MaxSizeKB = 10240
	}
	return c
}

// 站点级 Access 三态。判定实现只有一处，在 wafenginecore/accessgate.IsAccessEnabled。
const (
	AccessModeInherit  = 0 // 继承全局总开关（默认）
	AccessModeForceOn  = 1 // 强制开启：全局关也要认证（单站点试点、只保护后台）
	AccessModeForceOff = 2 // 强制关闭：全局开也放行（对外公开的站点）
)

// HostAccessConfig 是统一访问认证的站点级配置。
//
// 全局配置在 model.AccessConfig（单行表），这里只放「这个站点要不要参与、有哪些例外」。
// 三态的存在是为了让全局开关真正可用：没有 ForceOff，用户就不敢开全局；
// 没有 ForceOn，用户想只保护一个后台站点就得先开全局再逐个关掉其余站点。
type HostAccessConfig struct {
	Mode             int    `json:"mode"`                //0继承全局(默认) 1强制开启 2强制关闭
	ExcludePaths     string `json:"exclude_paths"`       //本站免认证路径前缀，换行分隔
	RequireOtp       int    `json:"require_otp"`         //0继承全局 1本站强制 2本站豁免
	UnauthAction     string `json:"unauth_action"`       //""继承全局 auto|redirect|401
	AllowIPGroupCode string `json:"allow_ip_group_code"` //本站额外的免认证 IP 组
}

// ParseAccessConfig 解析站点级 Access 配置。
//
// 空字符串与解析失败都返回 Mode=0（继承全局）。这一点是升级兼容的关键：
// 存量站点的 access_json 列是 NULL/""，必须落在「继承」而不是「强制开」，
// 否则用户升级到新版本的瞬间全站要求登录。
func ParseAccessConfig(jsonStr string) HostAccessConfig {
	c := HostAccessConfig{Mode: AccessModeInherit}
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return HostAccessConfig{Mode: AccessModeInherit}
	}
	if c.Mode < AccessModeInherit || c.Mode > AccessModeForceOff {
		c.Mode = AccessModeInherit
	}
	switch c.UnauthAction {
	case "", AccessUnauthAuto, AccessUnauthRedirect, AccessUnauth401:
	default:
		c.UnauthAction = ""
	}
	return c
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

// CustomHeaderItem 自定义头信息项
type CustomHeaderItem struct {
	HeaderName  string `json:"header_name"`  // 头信息名称
	HeaderValue string `json:"header_value"` // 头信息值，支持内置变量
}

// CustomHeadersConfig 自定义头信息配置（用于请求头）
type CustomHeadersConfig struct {
	IsEnableCustomHeaders int                `json:"is_enable_custom_headers"` // 是否开启自定义头信息 1开启 0关闭
	Headers               []CustomHeaderItem `json:"headers"`                  // 自定义头信息列表
}

// CustomResponseHeaderRule 自定义响应头规则（类似 nginx location 块）
// MatchType 支持: global(全局) / prefix(路径前缀) / suffix(文件后缀) / exact(精确路径) / regex(正则)
// MergeMode 支持: merge(与全局规则合并，同名以本规则为准) / override(仅使用本规则，忽略全局)
type CustomResponseHeaderRule struct {
	RuleName   string             `json:"rule_name"`   // 规则名称，方便识别
	MatchType  string             `json:"match_type"`  // global / prefix / suffix / exact / regex
	MatchValue string             `json:"match_value"` // 匹配值；suffix 用分号分隔，如 ".mp4;.mp3;.webm"
	Headers    []CustomHeaderItem `json:"headers"`     // 该规则的响应头列表
	MergeMode  string             `json:"merge_mode"`  // merge(默认) / override
}

// CustomResponseHeadersConfig 自定义响应头配置（V2 支持多规则路径匹配）
type CustomResponseHeadersConfig struct {
	IsEnableCustomHeaders int                        `json:"is_enable_custom_headers"` // 是否开启 1开启 0关闭
	Rules                 []CustomResponseHeaderRule `json:"rules"`                    // 规则列表（V2）
	Headers               []CustomHeaderItem         `json:"headers,omitempty"`        // 兼容旧版扁平列表
}

// defaultResponseCompressMimeTypes 与 nginx gzip_types 常见默认类似
var defaultResponseCompressMimeTypes = []string{
	"text/html",
	"text/plain",
	"text/css",
	"text/javascript",
	"text/xml",
	"application/json",
	"application/javascript",
	"application/x-javascript",
	"application/xml",
	"application/rss+xml",
	"application/atom+xml",
	"image/svg+xml",
}

// ParseResponseCompressConfig 解析响应压缩配置
func ParseResponseCompressConfig(jsonStr string) ResponseCompressConfig {
	var c ResponseCompressConfig
	c.IsEnable = 0
	c.Prefer = "zstd_first"
	c.MinLength = 256
	c.CompressWhenStaticAssist = 0
	if jsonStr == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return ResponseCompressConfig{
			IsEnable: 0, Prefer: "zstd_first", MinLength: 256, CompressWhenStaticAssist: 0,
		}
	}
	if c.Prefer == "" {
		c.Prefer = "zstd_first"
	}
	if c.MinLength <= 0 {
		c.MinLength = 256
	}
	return c
}

// DefaultResponseCompressMimeTypes 返回内置默认 MIME 列表（供引擎匹配）
func DefaultResponseCompressMimeTypes() []string {
	return append([]string(nil), defaultResponseCompressMimeTypes...)
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
	defense.DEFENSE_AI = 0

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

// ParseCustomHeadersConfig 解析自定义头信息配置
func ParseCustomHeadersConfig(customHeadersJSON string) CustomHeadersConfig {
	var config CustomHeadersConfig

	// 设置默认值
	config.IsEnableCustomHeaders = 0
	config.Headers = []CustomHeaderItem{}

	// 如果JSON不为空，则解析覆盖默认值
	if customHeadersJSON != "" {
		err := json.Unmarshal([]byte(customHeadersJSON), &config)
		if err != nil {
			// 解析失败时使用默认值，可以记录日志
			return config
		}
	}
	return config
}

// ParseCustomResponseHeadersConfig 解析自定义响应头信息配置（支持 V2 多规则格式和旧版扁平格式）
// 旧格式（只有 headers 字段）会自动转换为一条 global 规则，保持向后兼容。
func ParseCustomResponseHeadersConfig(customResponseHeadersJSON string) CustomResponseHeadersConfig {
	var config CustomResponseHeadersConfig
	config.IsEnableCustomHeaders = 0
	config.Rules = []CustomResponseHeaderRule{}

	if customResponseHeadersJSON == "" {
		return config
	}

	if err := json.Unmarshal([]byte(customResponseHeadersJSON), &config); err != nil {
		return config
	}

	// 向后兼容：若 rules 为空但存在旧版 headers 字段，转换为一条 global 规则
	if len(config.Rules) == 0 && len(config.Headers) > 0 {
		config.Rules = []CustomResponseHeaderRule{
			{
				RuleName:   "全局默认",
				MatchType:  "global",
				MatchValue: "",
				MergeMode:  "merge",
				Headers:    config.Headers,
			},
		}
		config.Headers = nil
	}

	// 为每条规则设置默认值
	for i := range config.Rules {
		if config.Rules[i].MatchType == "" {
			config.Rules[i].MatchType = "global"
		}
		if config.Rules[i].MergeMode == "" {
			config.Rules[i].MergeMode = "merge"
		}
		if config.Rules[i].Headers == nil {
			config.Rules[i].Headers = []CustomHeaderItem{}
		}
	}

	return config
}

// GetClientIPByMode 根据IP模式获取客户端IP
// ipMode: "nic" 网卡模式使用 NetSrcIp，"proxy" 代理模式使用 SRC_IP
// netSrcIp: 从网卡获取的IP (r.RemoteAddr)
// srcIP: 从代理头获取的IP (X-Forwarded-For等)
func GetClientIPByMode(ipMode string, netSrcIp string, srcIP string) string {
	if ipMode == "proxy" {
		return srcIP
	}
	// 默认使用网卡模式
	return netSrcIp
}

// HttpAuthConfig 「网站密码访问」的会话时效配置（hosts.HttpAuthJSON）。
//
// 兼容硬约束：HttpAuthJSON 为空串时（全部存量站点），DecodeHttpAuthConfig 必须还原成
// 「24 小时绝对有效期 + 绑定登录 IP + 不启用空闲超时」，即与加这套配置之前的行为逐条一致。
// 数值字段用 FlexInt 是因为前端表单回传的是字符串，普通 int 会让该字段悄悄回落默认值。
type HttpAuthConfig struct {
	SessionTTL  FlexInt `json:"session_ttl"`  // 绝对有效期(分钟)，<=0 视为默认 1440
	IdleTimeout FlexInt `json:"idle_timeout"` // 空闲超时(分钟)，0=不启用
	BindIP      FlexInt `json:"bind_ip"`      // 1=登录令牌绑定登录时的 IP(默认) 0=不绑
}

// 默认值。DefaultHttpAuthSessionTTL 对齐改造前硬编码的 24 小时。
const (
	DefaultHttpAuthSessionTTL = 1440 // 分钟
)

// DecodeHttpAuthConfig 解析站点的 http_auth_json。
//
// 空串、非法 JSON、字段缺省一律回落到「等价现状」而不是零值：
// 时效为 0 会让所有人一登录就掉线，BindIP 为 0 会静默放宽一条既有约束——
// 两者都属于「解析失败反而改变了防护行为」，这里不允许发生。
func DecodeHttpAuthConfig(raw string) HttpAuthConfig {
	cfg := HttpAuthConfig{
		SessionTTL:  DefaultHttpAuthSessionTTL,
		IdleTimeout: 0,
		BindIP:      1,
	}
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	var parsed HttpAuthConfig
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return cfg
	}
	if parsed.SessionTTL > 0 {
		cfg.SessionTTL = parsed.SessionTTL
	}
	if parsed.IdleTimeout > 0 {
		cfg.IdleTimeout = parsed.IdleTimeout
	}
	// BindIP 是显式三态：JSON 里给了 0 就是「用户主动关掉」，不能当成缺省再拉回 1。
	// 但整份 JSON 都没这个键时（老配置升级上来）必须保持 1，所以靠下面这次单独探测区分。
	cfg.BindIP = parsed.BindIP
	if !jsonHasKey(raw, "bind_ip") {
		cfg.BindIP = 1
	}
	return cfg
}

// jsonHasKey 判断顶层是否显式出现过某个键，用于区分「用户填了 0」与「压根没这个字段」。
func jsonHasKey(raw, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
