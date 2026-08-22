package request

import "SamWaf/model/common/request"

// WafUpgradeNoticeSearchReq 升级须知列表查询
type WafUpgradeNoticeSearchReq struct {
	Status  string `json:"status" form:"status"`   // pending / done / ignored，空=全部
	Kind    string `json:"kind" form:"kind"`       // notice / action / check，空=全部
	Version string `json:"version" form:"version"` // 按引入版本过滤，空=全部
	Lang    string `json:"lang" form:"lang"`       // zh_CN / en_US，空=中文
	request.PageInfo
}

// WafUpgradeNoticeIdReq 只接受条目 id。
//
// v2 的一键应用同样复用它：配置项名与目标值一律由后端从内置清单取，
// 绝不允许前端传 item/value，否则等于开了一个任意系统配置写入口。
type WafUpgradeNoticeIdReq struct {
	NoticeId string `json:"notice_id" form:"notice_id"`
}

// WafUpgradeNoticeSummaryReq 顶部提示条 / 弹窗用的汇总
type WafUpgradeNoticeSummaryReq struct {
	Lang string `json:"lang" form:"lang"`
}
