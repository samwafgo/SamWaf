package response

type LoginRep struct {
	AccessToken          string `json:"access_token"`           //访问授权码
	NeedChangePassword   bool   `json:"need_change_password"`   //是否需要强制改密(首次登录/被重置/口令到期)
	ChangePasswordReason string `json:"change_password_reason"` //需要改密的原因提示
	// 登录来源提醒：本次 IP/归属地，以及与上次是否一致。前端进入系统后在右下角弹出。
	LoginNotice LoginNoticeRep `json:"login_notice"`
}

// LoginNoticeRep 登录来源提醒
//
// 只带本次和上次两条，不带完整历史：弹窗上放不下，也没必要在登录这一步查全表，
// 想看更多走「登录历史」页面。
type LoginNoticeRep struct {
	CurrentIp   string `json:"current_ip"`   //本次登录IP
	CurrentArea string `json:"current_area"` //本次IP归属地
	CurrentTime string `json:"current_time"` //本次登录时间
	LastIp      string `json:"last_ip"`      //上次登录IP(首次登录为空)
	LastArea    string `json:"last_area"`    //上次登录IP归属地
	LastTime    string `json:"last_time"`    //上次登录时间
	IsFirst     bool   `json:"is_first"`     //是否首次登录(无上次记录)
	IsChanged   bool   `json:"is_changed"`   //本次与上次是否不一致
}
