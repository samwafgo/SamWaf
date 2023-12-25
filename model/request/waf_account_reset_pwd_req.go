package request

type WafAccountResetPwdReq struct {
	Id                 string `json:"id"`
	LoginAccount       string `json:"login_account" form:"login_account"`               //登录账号（TODO 账号是否能随便改）
	LoginSuperPassword string `json:"login_super_password" form:"login_super_password"` //密码md5加密
	LoginNewPassword   string `json:"login_new_password" form:"login_new_password"`     //新密码
	LoginNewPassword2  string `json:"login_new_password2" form:"login_new_password2"`   //确认密码
}
