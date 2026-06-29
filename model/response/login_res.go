package response

type LoginRep struct {
	AccessToken          string `json:"access_token"`           //访问授权码
	NeedChangePassword   bool   `json:"need_change_password"`   //是否需要强制改密(首次登录/被重置/口令到期)
	ChangePasswordReason string `json:"change_password_reason"` //需要改密的原因提示
}
