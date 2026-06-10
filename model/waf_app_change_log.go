package model

import "SamWaf/model/baseorm"

// WafAppChangeLog 应用配置变更记录（面向用户的字段级 diff，可从应用列表查看）
type WafAppChangeLog struct {
	baseorm.BaseOrm
	AppCode    string `gorm:"size:64;index"  json:"app_code"`    // 所属应用 code
	AppName    string `gorm:"size:128"       json:"app_name"`    // 操作时的应用名快照
	OpType     string `gorm:"size:32"        json:"op_type"`     // 操作类型：新增/修改/上传/升级/回滚
	Operator   string `gorm:"size:128"       json:"operator"`    // 操作账号
	OperatorIP string `gorm:"size:64"        json:"operator_ip"` // 操作来源 IP
	// Changes 存储 JSON 字符串，格式：[{"field":"start_cmd","label":"启动命令","old":"...","new":"..."}]
	// 上传/升级/回滚场景存文件名（+hash）信息
	Changes string `gorm:"type:text"      json:"changes"`
	Remarks string `gorm:"size:512"       json:"remarks"`
}
