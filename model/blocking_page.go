package model

import "SamWaf/model/baseorm"

const (
	// BlockingPageContentPrioritySamwaf 优先使用 SamWaf 自定义模版（默认，保持历史行为）：
	// 只要匹配上这条配置，无论后端有没有返回响应体，都用模版覆盖。
	BlockingPageContentPrioritySamwaf = "samwaf"
	// BlockingPageContentPriorityBackend 优先后端响应：
	// 后端已经返回了非空响应体（例如接口的 JSON 错误详情）时原样透传，
	// 只有后端没给响应体时才用自定义模版兜底。
	// 仅对"后端真实返回的状态码"生效；WAF 自身拦截（未到达后端）始终走模版。
	BlockingPageContentPriorityBackend = "backend"
)

// BlockingPage 自定义拦截模板界面
type BlockingPage struct {
	baseorm.BaseOrm
	BlockingPageName string `gorm:"size:255" json:"blocking_page_name"` //自定义拦截模板页面名称
	BlockingType     string `gorm:"size:50" json:"blocking_type"`       //自定义类型 被拦截
	AttackType       string `gorm:"size:100" json:"attack_type"`        //攻击类型 如: cc_attack, sensitive_word, sql_injection等
	HostCode         string `gorm:"size:64" json:"host_code"`           //适用于某个网站唯一码
	ResponseCode     string `gorm:"size:10" json:"response_code"`       //响应代码 默认403
	ResponseHeader   string `gorm:"type:text" json:"response_header"`   //响应Header头信息（JSON）
	ResponseContent  string `gorm:"type:text" json:"response_content"`  //响应内容
	ContentPriority  string `gorm:"size:20" json:"content_priority"`    //内容优先级 samwaf=优先自定义模版(默认,空值等同) backend=优先后端响应
}

// IsBackendContentFirst 是否为「优先后端响应」模式（空值按默认的 samwaf 处理，保证老数据行为不变）
func (b *BlockingPage) IsBackendContentFirst() bool {
	return b.ContentPriority == BlockingPageContentPriorityBackend
}
