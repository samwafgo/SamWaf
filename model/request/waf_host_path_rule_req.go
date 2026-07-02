package request

import "SamWaf/model/common/request"

type WafHostPathRuleAddReq struct {
	HostCode        string `json:"host_code"`
	RuleName        string `json:"rule_name"`
	Path            string `json:"path"`
	MatchType       int    `json:"match_type"`
	Priority        int    `json:"priority"`
	TargetType      int    `json:"target_type"`
	StripPrefix     int    `json:"strip_prefix"`
	RemoteHost      string `json:"remote_host"`
	RemotePort      int    `json:"remote_port"`
	RemoteIP        string `json:"remote_ip"`
	RemoteScheme    string `json:"remote_scheme"`
	RecordAccessLog int    `json:"record_access_log"`
	ResponseTimeOut int    `json:"response_time_out"`
	StaticRoot      string `json:"static_root"`
	SpaFallback     int    `json:"spa_fallback"`
	RedirectURL     string `json:"redirect_url"`
	RedirectCode    int    `json:"redirect_code"`
	Remarks         string `json:"remarks"`
}

type WafHostPathRuleEditReq struct {
	Id              string `json:"id"`
	HostCode        string `json:"host_code"`
	RuleName        string `json:"rule_name"`
	Path            string `json:"path"`
	MatchType       int    `json:"match_type"`
	Priority        int    `json:"priority"`
	TargetType      int    `json:"target_type"`
	StripPrefix     int    `json:"strip_prefix"`
	RemoteHost      string `json:"remote_host"`
	RemotePort      int    `json:"remote_port"`
	RemoteIP        string `json:"remote_ip"`
	RemoteScheme    string `json:"remote_scheme"`
	RecordAccessLog int    `json:"record_access_log"`
	ResponseTimeOut int    `json:"response_time_out"`
	StaticRoot      string `json:"static_root"`
	SpaFallback     int    `json:"spa_fallback"`
	RedirectURL     string `json:"redirect_url"`
	RedirectCode    int    `json:"redirect_code"`
	Remarks         string `json:"remarks"`
}

type WafHostPathRuleDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafHostPathRuleDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafHostPathRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	request.PageInfo
}
