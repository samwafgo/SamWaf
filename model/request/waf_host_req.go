package request

import "SamWaf/model/common/request"

type WafHostAddReq struct {
	Code                 string `json:"code"`                     //唯一编码
	Host                 string `json:"host"`                     //域名
	Port                 int    `json:"port"`                     //端口
	Ssl                  int    `json:"ssl"`                      //是否是ssl
	REMOTE_SYSTEM        string `json:"remote_system"`            //是宝塔 phpstudy等
	REMOTE_APP           string `json:"remote_app"`               //是什么类型的应用
	Remote_host          string `json:"remote_host"`              //远端域名
	Remote_ip            string `json:"remote_ip"`                //远端指定IP
	Remote_port          int    `json:"remote_port"`              //远端端口
	REMARKS              string `json:"remarks"`                  //备注
	Certfile             string `json:"certfile"`                 // 证书文件
	Keyfile              string `json:"keyfile"`                  // 密钥文件
	DEFENSE_JSON         string `json:"defense_json"`             //自身防御 json
	START_STATUS         int    `json:"start_status"`             //启动状态
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
	ResponseTimeOut      int    `json:"response_time_out"`        //响应超时时间
	HealthyJSON          string `json:"healthy_json"`             //后端健康度检测 json
	InsecureSkipVerify   int    `json:"insecure_skip_verify"`     //是否开启后端https证书有效性验证 默认 0 是校验 1 是不校验
	CaptchaJSON          string `json:"captcha_json"`             //验证码配置 json
	AntiLeechJSON        string `json:"anti_leech_json"`          //防盗链配置 json
	CacheJSON            string `json:"cache_json"`               //缓存配置 json
	DefaultEncoding      string `json:"default_encoding"`         //默认编码 utf-8 或者 gbk auto字符串自动选择
}

type WafHostDelReq struct {
	CODE string `json:"code"`
}

type WafHostDetailReq struct {
	CODE string `json:"code"`
}

type WafHostEditReq struct {
	CODE                 string `json:"code"`
	Host                 string `json:"host"`                     //域名
	Port                 int    `json:"port"`                     //端口
	Ssl                  int    `json:"ssl"`                      //是否是ssl
	REMOTE_SYSTEM        string `json:"remote_system"`            //是宝塔 phpstudy等
	REMOTE_APP           string `json:"remote_app"`               //是什么类型的应用
	Remote_host          string `json:"remote_host"`              //远端域名
	Remote_ip            string `json:"remote_ip"`                //远端指定IP
	Remote_port          int    `json:"remote_port"`              //远端端口
	REMARKS              string `json:"remarks"`                  //备注
	Certfile             string `json:"certfile"`                 // 证书文件
	Keyfile              string `json:"keyfile"`                  // 密钥文件
	DEFENSE_JSON         string `json:"defense_json"`             //自身防御 json
	START_STATUS         int    `json:"start_status"`             //启动状态
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
	ResponseTimeOut      int    `json:"response_time_out"`        //响应超时时间
	HealthyJSON          string `json:"healthy_json"`             //后端健康度检测 json
	InsecureSkipVerify   int    `json:"insecure_skip_verify"`     //是否开启后端https证书有效性验证 默认 0 是校验 1 是不校验
	CaptchaJSON          string `json:"captcha_json"`             //验证码配置 json
	AntiLeechJSON        string `json:"anti_leech_json"`          //防盗链配置 json
	CacheJSON            string `json:"cache_json"`               //缓存配置 json
	DefaultEncoding      string `json:"default_encoding"`         //默认编码 utf-8 或者 gbk auto字符串自动选择
}

type WafHostGuardStatusReq struct {
	CODE         string `json:"code"`
	GUARD_STATUS int    `json:"guard_status"` //防御状态 1 是开启防御 0 是防御关闭
}

type WafHostSearchReq struct {
	Code           string `json:"code" `                                  //主机码
	REMARKS        string `json:"remarks"`                                //备注
	SortBy         string `json:"sort_by" form:"sort_by"`                 //排序字段
	SortDescending string `json:"sort_descending" form:"sort_descending"` //排序方式
	FilterBy       string `json:"filter_by" form:"filter_by"`             //筛选字段
	FilterValue    string `json:"filter_value" form:"filter_value"`       //筛选值
	request.PageInfo
}

type WafHostStartStatusReq struct {
	CODE         string `json:"code"`
	START_STATUS int    `json:"start_status"` //启动状态
}

type WafHostAllDomainsReq struct {
	CODE string `json:"code" form:"code"`
}

type WafHostBatchGuardStatusReq struct {
	GUARD_STATUS int `json:"guard_status"` // 防御状态：0-关闭防御，1-开启防御
}
