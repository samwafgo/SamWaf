package response

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
)

type HostTodayStat struct {
	TodayPvCount     int64 `json:"today_pv_count"`     //今日PV
	TodayUvCount     int64 `json:"today_uv_count"`     //今日UV
	TodayAttackCount int64 `json:"today_attack_count"` //今日拦截数
	TodayTrafficIn   int64 `json:"today_traffic_in"`   //今日入站流量(bytes)
	TodayTrafficOut  int64 `json:"today_traffic_out"`  //今日出站流量(bytes)
}

type HostRep struct {
	model.Hosts
	RealTimeQps        int                         `json:"real_time_qps"`         //实时信息QPS
	RealTimeConnectCnt int                         `json:"real_time_connect_cnt"` //实时连接数量
	TodayPvCount       int64                       `json:"today_pv_count"`        //今日PV
	TodayUvCount       int64                       `json:"today_uv_count"`        //今日UV
	TodayAttackCount   int64                       `json:"today_attack_count"`    //今日拦截数
	TodayTrafficIn     int64                       `json:"today_traffic_in"`      //今日入站流量(bytes)
	TodayTrafficOut    int64                       `json:"today_traffic_out"`     //今日出站流量(bytes)
	HealthyStatus      []wafenginmodel.HostHealthy `json:"healthy_status"`        //当前健康情况
	PortConflict       bool                        `json:"port_conflict"`         //端口协议冲突标记（同端口被不同协议声明）
	ResolvedListens    []utils.HostListen          `json:"resolved_listens"`      //当前生效的端口监听表（派生结果，只读）
}
