package model

import (
	"SamWaf/model/baseorm"
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
	ResponseTimeOut      int    `json:"response_time_out"`        //响应超时时间 默认60秒,为0则无限等待
	HealthyJSON          string `json:"healthy_json"`             //后端健康度检测 json
	InsecureSkipVerify   int    `json:"insecure_skip_verify"`     //是否开启后端https证书有效性验证 默认 0 是校验 1 是不校验
	CaptchaJSON          string `json:"captcha_json"`             //验证码配置 json
	AntiLeechJSON        string `json:"anti_leech_json"`          //防盗链配置 json
	CacheJSON            string `json:"cache_json"`               //缓存配置 json
}

type HostsDefense struct {
	DEFENSE_BOT           int `json:"bot"`       //防御-虚假BOT
	DEFENSE_SQLI          int `json:"sqli"`      //防御-Sql注入
	DEFENSE_XSS           int `json:"xss"`       //防御-xss攻击
	DEFENSE_SCAN          int `json:"scan"`      //防御-scan工具扫描
	DEFENSE_RCE           int `json:"rce"`       //防御-scan工具扫描
	DEFENSE_SENSITIVE     int `json:"sensitive"` //敏感词检测
	DEFENSE_DIR_TRAVERSAL int `json:"traversal"` //目录穿越检测
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
