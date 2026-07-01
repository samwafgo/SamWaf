package request

import "SamWaf/model/common/request"

type WafTamperRuleAddReq struct {
	HostCode    string `json:"host_code" form:"host_code"`
	Url         string `json:"url" form:"url"`
	RuleName    string `json:"rule_name" form:"rule_name"`
	IsEnable    int    `json:"is_enable" form:"is_enable"`
	IgnoreQuery int    `json:"ignore_query" form:"ignore_query"`
	Remarks     string `json:"remarks" form:"remarks"`
}
type WafTamperRuleEditReq struct {
	Id          string `json:"id"`
	HostCode    string `json:"host_code" form:"host_code"`
	Url         string `json:"url" form:"url"`
	RuleName    string `json:"rule_name" form:"rule_name"`
	IsEnable    int    `json:"is_enable" form:"is_enable"`
	IgnoreQuery int    `json:"ignore_query" form:"ignore_query"`
	Remarks     string `json:"remarks" form:"remarks"`
}
type WafTamperRuleDetailReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleDelReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleRelearnReq struct {
	Id string `json:"id" form:"id"`
}

// WafTamperRuleBaselineReq 查看/下载基线正文
type WafTamperRuleBaselineReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	// 过滤（空/ nil 表示不过滤）
	Url            string `json:"url" form:"url"`
	RuleName       string `json:"rule_name" form:"rule_name"`
	IsEnable       *int   `json:"is_enable" form:"is_enable"`
	IgnoreQuery    *int   `json:"ignore_query" form:"ignore_query"`
	BaselineStatus *int   `json:"baseline_status" form:"baseline_status"`
	// 排序（OrderKey 走白名单，OrderDir=asc/desc）
	OrderKey string `json:"order_key" form:"order_key"`
	OrderDir string `json:"order_dir" form:"order_dir"`
	request.PageInfo
}

// WafTamperRuleRelearnBatchReq 批量/整站重新学习：Ids 为空表示整站全部
type WafTamperRuleRelearnBatchReq struct {
	HostCode string   `json:"host_code" form:"host_code"`
	Ids      []string `json:"ids" form:"ids"`
}

// WafTamperRuleExtractReq 从页面提取受保护 URL 候选（只抓当前站点后端）
type WafTamperRuleExtractReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	Domain   string `json:"domain" form:"domain"`     // 选定的站点域名（host 或 BindMoreHost 之一），作为抓取 Host 头与同站过滤基准
	PageUrl  string `json:"page_url" form:"page_url"` // 页面地址或路径（只取 path，走本站后端抓取）
}

// WafTamperRuleDelBatchReq 批量删除受保护 URL 规则（限定在 HostCode 内）
type WafTamperRuleDelBatchReq struct {
	HostCode string   `json:"host_code" form:"host_code"`
	Ids      []string `json:"ids" form:"ids"`
}

// WafTamperRuleAddBatchReq 批量新增受保护 URL 规则
type WafTamperRuleAddBatchReq struct {
	HostCode    string   `json:"host_code" form:"host_code"`
	Urls        []string `json:"urls" form:"urls"`
	IsEnable    int      `json:"is_enable" form:"is_enable"`
	IgnoreQuery int      `json:"ignore_query" form:"ignore_query"`
}
