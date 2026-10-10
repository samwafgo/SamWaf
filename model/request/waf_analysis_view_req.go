package request

// 来源与路径分析（M5 / G3）的三个只读查询。
// 都是 GET，gin 的 form 绑定只认 form tag，只写 json tag 会取不到值。

// WafAnalysisActorReq 行为视角：谁在打。
type WafAnalysisActorReq struct {
	Day      int    `json:"day" form:"day"`             //年月日 如 20260920，留空取今天
	HostCode string `json:"host_code" form:"host_code"` //留空=全部站点
	SortBy   string `json:"sort_by" form:"sort_by"`     //排序字段，服务端白名单映射，非法值回落默认
	Limit    int    `json:"limit" form:"limit"`         //Top N，默认 20
}

// WafAnalysisPathReq 目标视角：打哪里。
type WafAnalysisPathReq struct {
	Day      int    `json:"day" form:"day"`
	HostCode string `json:"host_code" form:"host_code"`
	SortBy   string `json:"sort_by" form:"sort_by"`
	Limit    int    `json:"limit" form:"limit"`
}

// WafAnalysisDetailReq 抽屉下钻：Kind=actor 看某个来源摸过什么，Kind=path 看某个路径被谁打。
type WafAnalysisDetailReq struct {
	Day      int    `json:"day" form:"day"`
	HostCode string `json:"host_code" form:"host_code"`
	Kind     string `json:"kind" form:"kind"` //actor | path
	Key      string `json:"key" form:"key"`   //actor_key 或 path_norm
	Limit    int    `json:"limit" form:"limit"`
}
