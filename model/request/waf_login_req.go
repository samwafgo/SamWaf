package request

type WafLoginReq struct {
	LoginAccount  string `json:"login_account" form:"login_account"`   //登录账号
	LoginPassword string `json:"login_password" form:"login_password"` //密码md5加密
}
