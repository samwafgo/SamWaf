package model

import "SamWaf/model/baseorm"

type Hosts struct {
	baseorm.BaseOrm
	Code                 string `json:"code"`                     //唯一码
	Host                 string `json:"host"`                     //域名
	Port                 int    `json:"port"`                     //端口
	Ssl                  int    `json:"ssl"`                      //是否是ssl
	GUARD_STATUS         int    `json:"guard_status"`             //防御状态
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
