package request

type WafHostEditReq struct {
	CODE          string `json:"code"`
	Host          string `json:"host"`          //域名
	Port          int    `json:"port"`          //端口
	Ssl           int    `json:"ssl"`           //是否是ssl
	REMOTE_SYSTEM string `json:"remote_system"` //是宝塔 phpstudy等
	REMOTE_APP    string `json:"remote_app"`    //是什么类型的应用
	Remote_host   string `json:"remote_host"`   //远端域名
	Remote_port   int    `json:"remote_port"`   //远端端口
	REMARKS       string `json:"remarks"`       //备注
}
