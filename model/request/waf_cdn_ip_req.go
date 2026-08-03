package request

import "SamWaf/model/common/request"

// WafCDNProviderRangesReq 分页浏览某厂商回源段(只读)
type WafCDNProviderRangesReq struct {
	Provider string `json:"provider" binding:"required"`
	Keyword  string `json:"keyword"`
	request.PageInfo
}

// WafCDNProviderAutoFetchReq 开/关自动拉取
type WafCDNProviderAutoFetchReq struct {
	Provider     string `json:"provider" binding:"required"`
	AutoFetch    int    `json:"auto_fetch"`    // 0 关 / 1 开
	IntervalHour int    `json:"interval_hour"` // 拉取周期(小时)，可选
}

// WafCDNProviderCredentialReq 保存认证型厂商凭证(不回显)
type WafCDNProviderCredentialReq struct {
	Provider   string `json:"provider" binding:"required"`
	SecretId   string `json:"secret_id"`   // SecretId/AccessKeyId，空=不改动
	SecretKey  string `json:"secret_key"`  // SecretKey/AccessKeySecret，空=不改动
	ExtraParam string `json:"extra_param"` // 非密参数 JSON(zone_id/domain/region)
}

// WafCDNProviderRefreshReq 立即拉取/清空凭证
type WafCDNProviderRefreshReq struct {
	Provider string `json:"provider" binding:"required"`
}
