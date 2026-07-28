package request

// WafUIPreferenceGetReq 获取界面偏好
// 说明：login_account 不允许由前端传入，只从 gin context（auth 中间件写入）取，防越权改他人配置
type WafUIPreferenceGetReq struct {
	PrefName string `json:"pref_name" form:"pref_name" binding:"required"`
}

// WafUIPreferenceSaveReq 保存界面偏好
type WafUIPreferenceSaveReq struct {
	PrefName string `json:"pref_name" form:"pref_name" binding:"required"`
	PrefJson string `json:"pref_json" form:"pref_json"`
}
