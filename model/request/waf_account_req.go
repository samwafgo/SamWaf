package request

import "SamWaf/model/common/request"

type WafAccountAddReq struct {
	LoginAccount  string `json:"login_account" form:"login_account"`   //登录账号
	LoginPassword string `json:"login_password" form:"login_password"` //密码md5加密
	Role          string `json:"role" form:"role"`                     //帐号角色
	Status        int    `json:"status" form:"status"  `               //状态
	Remarks       string `json:"remarks" form:"remarks"  `             //备注
}
type WafAccountResetPwdReq struct {
	Id                 string `json:"id"`
	LoginAccount       string `json:"login_account" form:"login_account"`               //登录账号（TODO 账号是否能随便改）
	LoginSuperPassword string `json:"login_super_password" form:"login_super_password"` //密码md5加密
	LoginNewPassword   string `json:"login_new_password" form:"login_new_password"`     //新密码
	LoginNewPassword2  string `json:"login_new_password2" form:"login_new_password2"`   //确认密码
}
type WafAccountSearchReq struct {
	LoginAccount string `json:"login_account" form:"login_account"` //登录账号
	request.PageInfo
}
type WafAccountDelReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}

type WafAccountDetailReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}
type WafAccountEditReq struct {
	Id            string `json:"id"`
	LoginAccount  string `json:"login_account" form:"login_account"`   //登录账号（TODO 账号是否能随便改）
	LoginPassword string `json:"login_password" form:"login_password"` //密码md5加密
	Role          string `json:"role" form:"role"`                     //帐号角色（留空则不修改）
	Status        int    `json:"status" form:"status"  `               //状态
	Remarks       string `json:"remarks" form:"remarks"  `             //备注
}

// WafAccountChangeMyPwdReq 当前登录账号自助改密（用于首次登录/到期强制改密）
type WafAccountChangeMyPwdReq struct {
	OldPassword  string `json:"old_password" form:"old_password"`   //旧密码
	NewPassword  string `json:"new_password" form:"new_password"`   //新密码
	NewPassword2 string `json:"new_password2" form:"new_password2"` //确认新密码
}

type WafAccountResetOTPReq struct {
	Id           string `json:"id"`
	LoginAccount string `json:"login_account" form:"login_account"` //登录账号
}
