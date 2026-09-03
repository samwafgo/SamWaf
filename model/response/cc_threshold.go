package response

// CCThresholdTopRep 单个客户端（统计维度取值）在样本期内的表现，供前端画分布图。
type CCThresholdTopRep struct {
	DimValue string `json:"dim_value"`
	Peak     int64  `json:"peak"`  // 单个统计周期内的最高请求数
	Total    int64  `json:"total"` // 样本期内的总请求数
}

// CCThresholdRep 按历史流量推荐 CC 阈值的结果。
//
// Supported=false 时只有 Reason（和可能的 Reference）有意义：
// 与其给一个看起来很准的错数，不如说清楚为什么算不出来——
// 用户拿推荐值去配封禁，错了是真实访客被挡在外面。
type CCThresholdRep struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason"`
	Reference string `json:"reference"` // 样本不足时给的业界参考值（含来源）

	Days      int  `json:"days"`       // 实际使用的天数（可能因降级而小于请求值）
	WindowSec int  `json:"window_sec"` // 实际使用的统计周期
	Sampled   bool `json:"sampled"`    // 是否因数据量过大而缩短了天数

	// ScopeNote 说明本次样本没能完全按规则条件收窄（例如规则还带了 UA/地域条件）。
	// 空串表示口径完整。
	ScopeNote string `json:"scope_note"`

	TotalReq int64 `json:"total_req"` // 样本请求数
	TotalDim int64 `json:"total_dim"` // 样本里出现过的统计维度取值个数

	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
	Max int64 `json:"max"`

	Loose    int64 `json:"loose"`    // P99×5
	Balanced int64 `json:"balanced"` // P99×3（默认）
	Strict   int64 `json:"strict"`   // P99×1.5

	Top []CCThresholdTopRep `json:"top"`
}
