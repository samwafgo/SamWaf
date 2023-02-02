package request

type WafAccountEditReq struct {
	Id            string `json:"id"`
	LoginAccount  string `json:"login_account" form:"login_account"`   //登录账号（TODO 账号是否能随便改）
	LoginPassword string `json:"login_password" form:"login_password"` //密码md5加密
	Status        int    `json:"status" form:"status"  `               //状态
	Remarks       string `json:"remarks" form:"remarks"  `             //备注
}
