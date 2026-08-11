package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"fmt"

	"github.com/gin-gonic/gin"
)

// WafThreatIPExcludeApi 威胁情报误报排除名单。
//
// 排除是**主动降低防护**的动作，所以这一层比普通 CRUD 多两件事：
//  1. 入参严格校验（尤其要挡掉巨型网段，排除一个 /0 等于把威胁情报功能悄悄关掉）
//  2. 每个写操作都带上操作人与来源 IP 落审计流水
type WafThreatIPExcludeApi struct {
}

// operatorOf 取当前操作人与来源 IP。
// 来源 IP 用 GetManageClientIP(带可信代理校验)，不能用 gin 默认的 c.ClientIP()——
// 后者信任全网转发头，审计里记下的可能是攻击者伪造的地址。
func operatorOf(c *gin.Context) (string, string) {
	account := ""
	if v, ok := c.Get("loginAccount"); ok {
		account, _ = v.(string)
	}
	if account == "" {
		account = "unknown"
	}
	return account, utils.GetManageClientIP(c)
}

// AddApi 新增排除条目
func (w *WafThreatIPExcludeApi) AddApi(c *gin.Context) {
	var req request.WafThreatIPExcludeAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if len(req.Remarks) > 500 {
		response.FailWithMessage("备注长度不能超过500个字符", c)
		return
	}
	operator, operatorIP := operatorOf(c)
	res, err := wafThreatIPExcludeService.AddApi(req, operator, operatorIP)
	if err != nil {
		response.FailWithMessage("添加失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(res, addResultMessage(res), c)
}

// addResultMessage 把"实际影响了什么"直接告诉用户。
// 影响为 0 时必须说清楚可能的原因——最典型的是排除了 1.2.3.4，
// 而快照里其实是 1.2.3.0/24，小的排不掉大的，用户光看"添加成功"会以为已经生效了。
func addResultMessage(res *waf_service.PreviewResult) string {
	if res.AffectedItems > 0 {
		return fmt.Sprintf("添加成功：已从 %d 个渠道剔除 %d 条，WAF 层已即时生效，系统防火墙正在后台重建",
			res.AffectedChans, res.AffectedItems)
	}
	if res.CoveringEntry != "" {
		return fmt.Sprintf("添加成功，但**未匹配到任何威胁情报条目**：该地址属于网段 %s，需要排除整段才会生效", res.CoveringEntry)
	}
	return "添加成功，但未匹配到任何威胁情报条目（该地址当前不在任何启用渠道的情报里，排除条目会一直保留并对后续同步生效）"
}

// PreviewApi 试算一条排除条目的影响，不落库。前端在用户点保存前调用。
func (w *WafThreatIPExcludeApi) PreviewApi(c *gin.Context) {
	var req request.WafThreatIPExcludePreviewReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	res, err := wafThreatIPExcludeService.Preview(req.Entry)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(res, "试算完成", c)
}

// ModifyApi 修改备注 / 启停
func (w *WafThreatIPExcludeApi) ModifyApi(c *gin.Context) {
	var req request.WafThreatIPExcludeEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if len(req.Remarks) > 500 {
		response.FailWithMessage("备注长度不能超过500个字符", c)
		return
	}
	if req.Enable != 0 && req.Enable != 1 {
		response.FailWithMessage("启用状态取值非法", c)
		return
	}
	operator, operatorIP := operatorOf(c)
	if err := wafThreatIPExcludeService.ModifyApi(req, operator, operatorIP); err != nil {
		response.FailWithMessage("修改失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("修改成功，正在后台重新落地", c)
}

// DelApi 删除排除条目（该地址将重新按威胁情报拦截）
func (w *WafThreatIPExcludeApi) DelApi(c *gin.Context) {
	var req request.WafThreatIPExcludeDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	operator, operatorIP := operatorOf(c)
	if err := wafThreatIPExcludeService.DelApi(req.Id, operator, operatorIP); err != nil {
		response.FailWithMessage("删除失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("删除成功，该地址将重新按威胁情报拦截，正在后台重新落地", c)
}

// GetListApi 分页查询排除名单
func (w *WafThreatIPExcludeApi) GetListApi(c *gin.Context) {
	var req request.WafThreatIPExcludeSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafThreatIPExcludeService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// EffectiveRulesApi 列出当前生效的内置排除规则。
//
// 内置来源(回环/本机网卡/内网段/管理端白名单/活跃管理会话)不落库，
// 只看排除名单表的话，用户会看到"已排除6条"却在名单里找不到任何条目。
// 降低防护的规则必须全部可见，哪怕是系统内置的。
func (w *WafThreatIPExcludeApi) EffectiveRulesApi(c *gin.Context) {
	response.OkWithDetailed(wafThreatIPExcludeService.EffectiveRules(), "获取成功", c)
}

// GetAuditListApi 分页查询排除操作审计流水
func (w *WafThreatIPExcludeApi) GetAuditListApi(c *gin.Context) {
	var req request.WafThreatIPExcludeAuditSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafThreatIPExcludeAuditService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}
