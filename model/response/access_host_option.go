package response

// AccessCenterHostOption 认证中心域名的候选项。
//
// 认证中心必须是一个已经在【网站维护】里配好的站点（否则请求根本进不到引擎，
// 跳过去就是 403 死循环），所以这个列表直接由站点表推导出来，
// 让用户在下拉里点一下就填好，不用自己拼 scheme 和端口。
type AccessCenterHostOption struct {
	Origin   string `json:"origin"`    //完整地址，如 https://sso.example.com（直接填进配置）
	Label    string `json:"label"`     //下拉里显示的文案：地址 + 昵称/备注
	HostCode string `json:"host_code"` //来源站点唯一码
}
