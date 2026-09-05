package request

import "SamWaf/model/common/request"

// ─────────────── 网站密码访问：在线会话 ───────────────

type WafHttpAuthSessionSearchReq struct {
	HostCode string `json:"host_code" binding:"required"` //必填，会话按站点隔离
	UserName string `json:"user_name"`
	ClientIP string `json:"client_ip"`
	Status   *int   `json:"status"` //用指针：不传=全部，传0=只看已失效；普通 int 的零值会让「全部」永远查不出有效会话
	request.PageInfo
}

// WafHttpAuthSessionKickReq 走 GET，参数在 query 里。
// form tag 不能省：GET 用的是 gin 的 form 绑定，它只认 form tag，
// 只写 json tag 的话取不到值，加上 binding:"required" 就直接报「解析失败」。
type WafHttpAuthSessionKickReq struct {
	Id string `json:"id" form:"id" binding:"required"` //会话主键，服务端据此反查 token_code
}

type WafHttpAuthSessionKickByUserReq struct {
	HostCode string `json:"host_code" binding:"required"`
	UserName string `json:"user_name" binding:"required"`
}

type WafHttpAuthSessionKickAllReq struct {
	HostCode string `json:"host_code" binding:"required"`
}
