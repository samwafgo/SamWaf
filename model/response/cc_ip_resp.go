package response

type CcIpRep struct {
	IP         string `json:"ip"`          //IP
	RemainTime string `json:"remain_time"` //剩余封禁时间
	Region     string `json:"region"`      //ip归属地
}
