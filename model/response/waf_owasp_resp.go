package response

import "SamWaf/wafowasp"

// WafOwaspRuleListItem 前端展示用的规则条目。
type WafOwaspRuleListItem struct {
	wafowasp.RuleMeta
	Disabled bool `json:"disabled"`
	Modified bool `json:"modified"`
}

// WafOwaspDryRunHit 单条规则命中记录。
type WafOwaspDryRunHit struct {
	ID       int      `json:"id"`
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Phase    int      `json:"phase"`
	File     string   `json:"file"`
	Tags     []string `json:"tags"`
	Paranoia int      `json:"paranoia"` // 从 tag:paranoia-level/N 提取，0 表示未标记（任意 PL 生效）
}

// WafOwaspDryRunResp 沙盒测试响应。
type WafOwaspDryRunResp struct {
	Interrupted       bool                `json:"interrupted"`
	InterruptID       int                 `json:"interrupt_rule_id"`
	InterruptData     string              `json:"interrupt_data"`
	AnomalyScore      int                 `json:"anomaly_score"`      // = blocking_inbound_anomaly_score
	DetectionScore    int                 `json:"detection_score"`    // = detection_inbound_anomaly_score
	BlockingThreshold int                 `json:"blocking_threshold"` // 当前配置的入站拦截阈值
	BlockingParanoia  int                 `json:"blocking_paranoia"`  // 当前拦截 PL
	DetectionParanoia int                 `json:"detection_paranoia"` // 当前检测 PL
	Hits              []WafOwaspDryRunHit `json:"hits"`
}
