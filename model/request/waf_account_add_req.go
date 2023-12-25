package request

type WafAccountAddReq struct {
	LoginAccount  string `json:"login_account" form:"login_account"`   //登录账号
	LoginPassword string `json:"login_password" form:"login_password"` //密码md5加密
	Role          string `json:"role" form:"role"`                     //帐号角色
	Status        int    `json:"status" form:"status"  `               //状态
	Remarks       string `json:"remarks" form:"remarks"  `             //备注
}
