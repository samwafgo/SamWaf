package response

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

type HostRep struct {
	model.Hosts
	RealTimeQps        int                         `json:"real_time_qps"`         //实时信息QPS
	RealTimeConnectCnt int                         `json:"real_time_connect_cnt"` //实时连接数量
	HealthyStatus      []wafenginmodel.HostHealthy `json:"healthy_status"`        //当前健康情况
}
