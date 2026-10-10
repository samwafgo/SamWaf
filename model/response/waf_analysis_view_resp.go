package response

// 来源与路径分析（M5 / G3）的返回结构。
// 去重数（distinct_path / distinct_actor）都是查询时 COUNT(DISTINCT) 现算的，
// 库里没有这两列——去重计数没法跨批次累加，存成列必错（见计划 §5.7）。

// WafAnalysisActorRow 行为视角一行：一个来源今天干了什么。
type WafAnalysisActorRow struct {
	ActorKey     string `json:"actor_key"`     //ip:1.2.3.4
	ReqCnt       int64  `json:"req_cnt"`       //请求数
	DenyCnt      int64  `json:"deny_cnt"`      //被拦截数
	Err4xxCnt    int64  `json:"err4xx_cnt"`    //后端返回的 4xx，不含 WAF 拦截页
	DistinctPath int64  `json:"distinct_path"` //摸过多少个不同路径模板——扫目录的信号
	UaCnt        int64  `json:"ua_cnt"`        //用过多少种 UA 指纹
}

// WafAnalysisActorResp 行为视角一页 + 该视角自己的几个统计数。
type WafAnalysisActorResp struct {
	Day           int                   `json:"day"`
	List          []WafAnalysisActorRow `json:"list"`
	TotalActor    int64                 `json:"total_actor"`    //今天出现过的不同来源数
	ScanActor     int64                 `json:"scan_actor"`     //达到扫目录阈值的来源数
	UaActor       int64                 `json:"ua_actor"`       //达到换 UA 阈值的来源数
	ScanThreshold int64                 `json:"scan_threshold"` //当前判定线，界面显示用
	UaThreshold   int64                 `json:"ua_threshold"`
}

// WafAnalysisPathRow 目标视角一行：一个路径模板今天被怎么打。
type WafAnalysisPathRow struct {
	PathNorm      string `json:"path_norm"`
	ReqCnt        int64  `json:"req_cnt"`
	DenyCnt       int64  `json:"deny_cnt"`
	Err4xxCnt     int64  `json:"err4xx_cnt"`
	DistinctActor int64  `json:"distinct_actor"` //几个不同来源打过它
	TopRule       string `json:"top_rule"`       //命中最多的规则，来自 stats_path_rule_days
}

type WafAnalysisPathResp struct {
	Day       int                  `json:"day"`
	List      []WafAnalysisPathRow `json:"list"`
	TotalPath int64                `json:"total_path"` //今天出现过的路径模板数
}

// 抽屉下钻的几张小表
type WafAnalysisDetailPath struct {
	PathNorm  string `json:"path_norm"`
	ReqCnt    int64  `json:"req_cnt"`
	DenyCnt   int64  `json:"deny_cnt"`
	Err4xxCnt int64  `json:"err4xx_cnt"`
}
type WafAnalysisDetailActor struct {
	ActorKey  string `json:"actor_key"`
	ReqCnt    int64  `json:"req_cnt"`
	DenyCnt   int64  `json:"deny_cnt"`
	Err4xxCnt int64  `json:"err4xx_cnt"`
}
type WafAnalysisDetailUa struct {
	UaHash string `json:"ua_hash"`
	Cnt    int64  `json:"cnt"`
}
type WafAnalysisDetailRule struct {
	Rule string `json:"rule"`
	Cnt  int64  `json:"cnt"`
}

// WafAnalysisDetailHost 这个来源打过哪些站点。
// 加黑/加白的接口 host_code 都是必填，而本页是跨站点聚合的，
// 一个来源可能横跨多站——界面靠这张表让用户选站点，不能瞎猜一个。
type WafAnalysisDetailHost struct {
	HostCode string `json:"host_code"`
	ReqCnt   int64  `json:"req_cnt"`
	DenyCnt  int64  `json:"deny_cnt"`
}

type WafAnalysisDetailResp struct {
	Kind      string                   `json:"kind"` //actor | path
	Key       string                   `json:"key"`
	ReqCnt    int64                    `json:"req_cnt"`
	DenyCnt   int64                    `json:"deny_cnt"`
	Err4xxCnt int64                    `json:"err4xx_cnt"`
	Paths     []WafAnalysisDetailPath  `json:"paths"`  //kind=actor
	Uas       []WafAnalysisDetailUa    `json:"uas"`    //kind=actor
	Hosts     []WafAnalysisDetailHost  `json:"hosts"`  //kind=actor
	Actors    []WafAnalysisDetailActor `json:"actors"` //kind=path
	Rules     []WafAnalysisDetailRule  `json:"rules"`  //kind=path
}
