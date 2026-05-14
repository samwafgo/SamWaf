package model

import "SamWaf/model/baseorm"

// HostPathRule 路径路由规则（类似 nginx location 块）
type HostPathRule struct {
	baseorm.BaseOrm
	HostCode    string `gorm:"size:64" json:"host_code"`  // 所属 host 代码
	RuleName    string `gorm:"size:255" json:"rule_name"` // 规则名称
	Path        string `gorm:"size:500" json:"path"`      // 匹配路径，如 /api/
	MatchType   int    `json:"match_type"`                // 1=前缀匹配 2=精确匹配 3=正则
	Priority    int    `json:"priority"`                  // 优先级，数字小越优先（默认100）
	TargetType  int    `json:"target_type"`               // 1=后端代理 2=静态文件 3=重定向
	StripPrefix int    `json:"strip_prefix"`              // 转发时是否去掉路径前缀 0否 1是

	// TargetType=1 后端代理
	RemoteHost string `gorm:"size:255" json:"remote_host"` // 远端域名
	RemotePort int    `json:"remote_port"`                 // 远端端口
	RemoteIP   string `gorm:"size:64" json:"remote_ip"`    // 远端指定IP（可空，空则解析域名）

	// TargetType=2 静态文件
	StaticRoot  string `gorm:"size:1000" json:"static_root"` // 本地静态文件目录路径
	SpaFallback int    `json:"spa_fallback"`                 // SPA回退模式 0=关闭 1=开启（文件不存在时回退到 index.html）

	// TargetType=3 重定向
	RedirectURL  string `gorm:"size:1000" json:"redirect_url"` // 重定向目标URL
	RedirectCode int    `json:"redirect_code"`                 // HTTP状态码 301/302，默认302

	Remarks string `gorm:"size:500" json:"remarks"` // 备注
}
