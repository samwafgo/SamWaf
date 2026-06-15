package model

import "SamWaf/model/baseorm"

/*
*
训练标签人工修正
针对单条访问日志（按 req_uuid）修正其训练标签，用于纠正规则误报导致的错误弱标签。
导出训练数据时优先采用此处的人工修正结果。
*/
type WafLogLabelMark struct {
	baseorm.BaseOrm
	REQ_UUID   string `gorm:"size:64;index" json:"req_uuid"` // 关联的请求日志
	HOST_CODE  string `gorm:"size:64" json:"host_code"`      // 主机码
	Mark       string `gorm:"size:20" json:"mark"`           // normal=实际正常 / attack=确认攻击 / ignore=不参与训练
	AttackType string `gorm:"size:32" json:"attack_type"`    // 当 mark=attack 时的人工分类(sqli/xss/rce/traversal/inject/scan/other)，空=用自动判定
	RULE       string `gorm:"type:text" json:"rule"`         // 原始触发规则（快照，便于审阅）
	SRC_IP     string `gorm:"size:64" json:"src_ip"`         // 来源IP（快照）
	URL        string `gorm:"type:text" json:"url"`          // 访问URL（快照）
	// 训练字段快照：标记时即固化，导出不受时间/条数条件影响，日志被清理也不丢
	METHOD     string `gorm:"size:20" json:"method"`      // 请求方法（快照）
	RAW_QUERY  string `gorm:"type:text" json:"raw_query"` // 查询串（快照）
	BODY       string `gorm:"type:text" json:"body"`      // 请求体（快照，body 或 post_form）
	USER_AGENT string `gorm:"size:500" json:"user_agent"` // UA（快照）
}
