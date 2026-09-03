package response

type CcIpRep struct {
	IP         string `json:"ip"`          //IP
	RemainTime string `json:"remain_time"` //剩余封禁时间
	Region     string `json:"region"`      //ip归属地
	Scope      string `json:"scope"`       //封禁作用域 global=全部站点 host=仅该站点
	HostCode   string `json:"host_code"`   //作用域为 host 时的站点码
	HostName   string `json:"host_name"`   //作用域为 host 时的站点主域名，供界面直接显示
}
