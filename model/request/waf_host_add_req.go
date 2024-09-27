package request

type WafHostAddReq struct {
	Code                string `json:"code"`                   //唯一编码
	Host                string `json:"host"`                   //域名
	Port                int    `json:"port"`                   //端口
	Ssl                 int    `json:"ssl"`                    //是否是ssl
	REMOTE_SYSTEM       string `json:"remote_system"`          //是宝塔 phpstudy等
	REMOTE_APP          string `json:"remote_app"`             //是什么类型的应用
	Remote_host         string `json:"remote_host"`            //远端域名
	Remote_ip           string `json:"remote_ip"`              //远端指定IP
	Remote_port         int    `json:"remote_port"`            //远端端口
	REMARKS             string `json:"remarks"`                //备注
	Certfile            string `json:"certfile"`               // 证书文件
	Keyfile             string `json:"keyfile"`                // 密钥文件
	DEFENSE_JSON        string `json:"defense_json"`           //自身防御 json
	START_STATUS        int    `json:"start_status"`           //启动状态
	EXCLUDE_URL_LOG     string `json:"exclude_url_log"`        //排除的url开头的数据 换行隔开
	IsEnableLoadBalance int    `json:"is_enable_load_balance"` //是否激活负载  1 激活  非1 没有激活
	LoadBalanceStage    int    `json:"load_balance_stage"`     //负载策略
}
