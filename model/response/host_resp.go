package response

import "SamWaf/model"

type HostRep struct {
	model.Hosts
	RealTimeQps        int `json:"real_time_qps"`         //实时信息QPS
	RealTimeConnectCnt int `json:"real_time_connect_cnt"` //实时连接数量
}
