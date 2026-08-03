package model

import "SamWaf/model/baseorm"

// CDNProvider CDN 厂商回源段中心库(每厂商一行)：统一存放各家回源 IP 段 + 拉取配置 + 认证凭证。
// 站点(真实IP来源=cdn_preset)与管理端(可信代理)都只引用厂商码、请求时读本库最新值，
// 一处更新处处生效，避免各处单独维护。
//
// 安全：
//   - SecretId/SecretKey 加密落库(wafsec)，API 永不回显(json:"-")，且整表被 waf_sql_query 封禁不可查询。
//   - AutoFetch 默认 0(关)：内置厂商不主动对外拉取，等有站点/管理端引用时提示用户去开启并手动触发一次。
type CDNProvider struct {
	baseorm.BaseOrm
	Provider     string `gorm:"size:32;index" json:"provider"` // 厂商码：cloudflare/fastly/cloudfront/edgeone/aliyun/akamai
	AutoFetch    int    `json:"auto_fetch"`                    // 是否定时自动拉取：0 关(默认) / 1 开
	IntervalHour int    `json:"interval_hour"`                 // 拉取周期(小时)，默认 24
	// 认证凭证(仅认证型厂商 edgeone/aliyun 用)：加密落库，API 绝不回显
	SecretId   string `gorm:"type:text" json:"-"`           // 加密后的 SecretId/AccessKeyId
	SecretKey  string `gorm:"type:text" json:"-"`           // 加密后的 SecretKey/AccessKeySecret
	ExtraParam string `gorm:"type:text" json:"extra_param"` // 非密参数 JSON(region/zone_id 等)
	// 最新回源段快照
	Count      int    `json:"count"`                       // 回源段条数
	Payload    []byte `gorm:"column:payload" json:"-"`     // gzip 压缩的回源段文本(\n 分隔)
	Sha256     string `gorm:"size:64" json:"-"`            // 快照指纹
	Source     string `gorm:"size:16" json:"source"`       // auto_public | auth_api | manual
	LastSyncAt int64  `json:"last_sync_at"`                // 上次成功拉取时间戳(秒)
	LastStatus string `gorm:"size:255" json:"last_status"` // 上次拉取结果
}

// TableName 表名(含 "cdn_provider" 子串，已在 waf_sql_query.go 封禁不可查询)
func (CDNProvider) TableName() string {
	return "cdn_provider"
}

// 回源段来源枚举
const (
	CDNSourceAutoPublic = "auto_public" // Tier A 匿名公开列表
	CDNSourceAuthAPI    = "auth_api"    // 认证 API(EdgeOne/阿里云)
	CDNSourceManual     = "manual"      // 用户手填
)
