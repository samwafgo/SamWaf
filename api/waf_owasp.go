package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafowasp"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gin-gonic/gin"
)

// WafOwaspApi OWASP 规则在线管理 API。
type WafOwaspApi struct{}

// manager 辅助：保证 manager 存在，否则返回 nil 并写失败响应。
func (w *WafOwaspApi) manager(c *gin.Context) *wafowasp.OwaspManager {
	m := global.GWAF_OWASP_MANAGER
	if m == nil {
		response.FailWithMessage("OWASP 管理器尚未初始化", c)
		return nil
	}
	return m
}

// RulesListApi 获取OWASP规则列表
// @Summary      获取OWASP规则列表
// @Description  扫描 coreruleset 目录，结合 overrides 注册表返回分页规则列表，支持按文件、严重级别、偏执级别、关键词、状态过滤
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        file        query     string  false  "文件名过滤（模糊匹配）"
// @Param        severity    query     string  false  "严重级别过滤（CRITICAL/ERROR/WARNING/NOTICE）"
// @Param        paranoia    query     int     false  "偏执级别过滤（1-4，0表示不过滤）"
// @Param        keyword     query     string  false  "关键词搜索（匹配 msg、ID、文件名）"
// @Param        status      query     string  false  "状态过滤（disabled/modified/default，空表示全部）"
// @Param        page_index  query     int     false  "页码，默认1"
// @Param        page_size   query     int     false  "每页条数，默认50，最大500"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/rules [get]
func (w *WafOwaspApi) RulesListApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	var req request.WafOwaspRulesListReq
	_ = c.ShouldBindQuery(&req)
	if req.PageIndex <= 0 {
		req.PageIndex = 1
	}
	if req.PageSize <= 0 || req.PageSize > 500 {
		req.PageSize = 50
	}

	owaspRoot := m.OwaspRoot()
	files, err := wafowasp.ScanAllRules(owaspRoot)
	if err != nil {
		response.FailWithMessage("扫描规则失败: "+err.Error(), c)
		return
	}

	reg, _ := m.Overrides().LoadRegistry()
	disabled := map[int]bool{}
	modified := map[int]bool{}
	if reg != nil {
		for k, v := range reg.Rules {
			id, err := strconv.Atoi(k)
			if err != nil {
				continue
			}
			if v.Action == wafowasp.OverrideDisabled {
				disabled[id] = true
			}
			if v.Action == wafowasp.OverrideModified {
				modified[id] = true
			}
		}
	}

	all := make([]response2.WafOwaspRuleListItem, 0, 2048)
	for _, f := range files {
		for _, r := range f.Rules {
			if req.File != "" && !strings.Contains(r.File, req.File) {
				continue
			}
			if req.Severity != "" && !strings.EqualFold(r.Severity, req.Severity) {
				continue
			}
			if req.Paranoia > 0 && r.Paranoia != req.Paranoia {
				continue
			}
			if req.Keyword != "" {
				kw := strings.ToLower(req.Keyword)
				if !strings.Contains(strings.ToLower(r.Message), kw) &&
					!strings.Contains(strconv.Itoa(r.ID), kw) &&
					!strings.Contains(strings.ToLower(r.File), kw) {
					continue
				}
			}
			isDisabled := disabled[r.ID]
			isModified := modified[r.ID]
			switch req.Status {
			case "disabled":
				if !isDisabled {
					continue
				}
			case "modified":
				if !isModified {
					continue
				}
			case "default":
				if isDisabled || isModified {
					continue
				}
			}
			all = append(all, response2.WafOwaspRuleListItem{
				RuleMeta: r,
				Disabled: isDisabled,
				Modified: isModified,
			})
		}
	}

	// 统计全量（不受分页影响）的禁用/改写数量，供前端快捷筛选徽标显示。
	var totalDisabled, totalModified int
	for _, entry := range reg.Rules {
		switch entry.Action {
		case wafowasp.OverrideDisabled:
			totalDisabled++
		case wafowasp.OverrideModified:
			totalModified++
		}
	}

	total := len(all)
	start := (req.PageIndex - 1) * req.PageSize
	if start > total {
		start = total
	}
	end := start + req.PageSize
	if end > total {
		end = total
	}

	response.OkWithDetailed(gin.H{
		"list":           all[start:end],
		"total":          total,
		"page_index":     req.PageIndex,
		"page_size":      req.PageSize,
		"disabled_count": totalDisabled,
		"modified_count": totalModified,
	}, "获取成功", c)
}

// RuleDetailApi 获取OWASP规则详情
// @Summary      获取OWASP规则详情
// @Description  根据规则 ID 返回规则原始内容及当前 override 状态（是否被改写/禁用及用户版本内容）
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        id  query     int  true  "规则ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/rule_detail [get]
func (w *WafOwaspApi) RuleDetailApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	idStr := c.Query("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		response.FailWithMessage("id 非法", c)
		return
	}
	files, err := wafowasp.ScanAllRules(m.OwaspRoot())
	if err != nil {
		response.FailWithMessage("扫描规则失败: "+err.Error(), c)
		return
	}
	var target *wafowasp.RuleMeta
	for _, f := range files {
		for i := range f.Rules {
			if f.Rules[i].ID == id {
				rm := f.Rules[i]
				target = &rm
				break
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		response.FailWithMessage("未找到该规则 ID", c)
		return
	}

	reg, _ := m.Overrides().LoadRegistry()
	var entry *wafowasp.RuleOverrideEntry
	if reg != nil {
		if e, ok := reg.Rules[idStr]; ok {
			entry = &e
		}
	}

	response.OkWithDetailed(gin.H{
		"rule":     target,
		"override": entry,
	}, "获取成功", c)
}

// RuleToggleApi 启用/禁用OWASP规则
// @Summary      启用/禁用OWASP规则
// @Description  启用或禁用指定规则，操作后立即热重载 WAF 使其生效
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOwaspRuleToggleReq  true  "规则启用/禁用配置"
// @Success      200   {object}  response.Response  "已生效（已热重载 WAF）"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/rule_toggle [post]
func (w *WafOwaspApi) RuleToggleApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	var req request.WafOwaspRuleToggleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if req.ID <= 0 {
		response.FailWithMessage("id 非法", c)
		return
	}

	var err error
	if req.Disabled {
		err = m.DisableRuleAndReload(req.ID, req.SourceFile)
	} else {
		err = m.EnableRuleAndReload(req.ID)
	}
	if err != nil {
		response.FailWithMessage("操作失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已生效（已热重载 WAF）", c)
}

// RuleOverrideApi 改写OWASP规则内容
// @Summary      改写OWASP规则内容
// @Description  用自定义内容覆盖指定规则，覆盖后立即热重载 WAF；原始规则内容哈希会被记录以便后续还原
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOwaspRuleOverrideReq  true  "规则改写内容"
// @Success      200   {object}  response.Response  "规则已改写并热重载"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/rule_override [post]
func (w *WafOwaspApi) RuleOverrideApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	var req request.WafOwaspRuleOverrideReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if req.ID <= 0 {
		response.FailWithMessage("id 非法", c)
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		response.FailWithMessage("content 不能为空", c)
		return
	}

	// 计算原始内容 hash（如果能从扫描里找到）
	originalHash := ""
	if files, err := wafowasp.ScanAllRules(m.OwaspRoot()); err == nil {
		for _, f := range files {
			for _, r := range f.Rules {
				if r.ID == req.ID {
					sum := sha256.Sum256([]byte(r.RawSnippet))
					originalHash = hex.EncodeToString(sum[:])
					if req.SourceFile == "" {
						req.SourceFile = r.File
					}
					break
				}
			}
		}
	}

	if err := m.OverrideRuleAndReload(req.ID, req.SourceFile, originalHash, req.Content); err != nil {
		response.FailWithMessage("操作失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("规则已改写并热重载", c)
}

// RuleResetApi 还原OWASP规则为上游版本
// @Summary      还原OWASP规则为上游版本
// @Description  删除指定规则的 override 记录，将其还原为 coreruleset 上游原始版本，并立即热重载 WAF
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOwaspRuleResetReq  true  "规则ID"
// @Success      200   {object}  response.Response  "已还原并热重载"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/rule_reset [post]
func (w *WafOwaspApi) RuleResetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	var req request.WafOwaspRuleResetReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if req.ID <= 0 {
		response.FailWithMessage("id 非法", c)
		return
	}
	if err := m.ResetRuleAndReload(req.ID); err != nil {
		response.FailWithMessage("操作失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已还原并热重载", c)
}

// AuditLogApi 获取OWASP规则变更审计日志
// @Summary      获取OWASP规则变更审计日志
// @Description  返回所有 override 操作的变更审计日志，按时间倒序排列（最新在前）
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/audit_log [get]
func (w *WafOwaspApi) AuditLogApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	entries, err := m.Overrides().LoadAuditLog()
	if err != nil {
		response.FailWithMessage("读取变更日志失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"entries": entries, "total": len(entries)}, "获取成功", c)
}

// CRSVarsGetApi 获取所有自定义CRS事务变量
// @Summary      获取所有自定义CRS事务变量
// @Description  返回当前所有用户自定义的 CRS 事务变量（tx.*）键值列表
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/crs_vars [get]
func (w *WafOwaspApi) CRSVarsGetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	vars, err := m.Overrides().GetCRSVars()
	if err != nil {
		response.FailWithMessage("读取失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"vars": vars}, "获取成功", c)
}

// CRSVarSetApi 设置单个CRS事务变量
// @Summary      设置单个CRS事务变量
// @Description  新增或更新单个 CRS 事务变量（tx.*），保存后立即热重载 WAF 使其生效
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOwaspCRSVarSetReq  true  "CRS 变量键值"
// @Success      200   {object}  response.Response  "CRS 变量已更新并热重载"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/crs_var [post]
func (w *WafOwaspApi) CRSVarSetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	var req request.WafOwaspCRSVarSetReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := m.Overrides().SetCRSVar(req.Key, req.Value); err != nil {
		response.FailWithMessage("设置失败: "+err.Error(), c)
		return
	}
	// 热重载使新变量立即生效
	if err := m.Reload(); err != nil {
		response.FailWithMessage("变量已保存，但热重载失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("CRS 变量已更新并热重载", c)
}

// CRSVarDeleteApi 删除单个CRS事务变量
// @Summary      删除单个CRS事务变量
// @Description  删除指定的 CRS 事务变量（tx.*），删除后立即热重载 WAF 使其生效
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        key  query     string  true  "变量名（可带或不带 tx. 前缀）"
// @Success      200  {object}  response.Response  "CRS 变量已删除并热重载"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/crs_var [delete]
func (w *WafOwaspApi) CRSVarDeleteApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	key := c.Query("key")
	if key == "" {
		response.FailWithMessage("key 不能为空", c)
		return
	}
	if err := m.Overrides().DeleteCRSVar(key); err != nil {
		response.FailWithMessage("删除失败: "+err.Error(), c)
		return
	}
	if err := m.Reload(); err != nil {
		response.FailWithMessage("变量已删除，但热重载失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("CRS 变量已删除并热重载", c)
}

// BaseConfigGetApi 获取OWASP基线配置
// @Summary      获取OWASP基线配置
// @Description  读取 Layer 1 基线配置（samwaf_base.json），包含偏执级别、异常分阈值等核心参数
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/base_config [get]
func (w *WafOwaspApi) BaseConfigGetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	cfg, err := m.Overrides().GetBaseConfig()
	if err != nil {
		response.FailWithMessage("读取失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(cfg, "获取成功", c)
}

// BaseConfigSetApi 更新OWASP基线配置
// @Summary      更新OWASP基线配置
// @Description  写入 Layer 1 基线配置并热重载；仅管理 CRS tx.* 数值变量，SecRuleEngine 和自定义变量不在此接口管理
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      object  true  "基线配置（blocking_paranoia_level、detection_paranoia_level、inbound_anomaly_score_threshold 等）"
// @Success      200   {object}  response.Response  "Layer 1 基线已更新并热重载"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/base_config [post]
func (w *WafOwaspApi) BaseConfigSetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	raw := map[string]interface{}{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	pickInt := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := raw[k]; ok && v != nil {
				switch n := v.(type) {
				case float64:
					return int(n)
				case int:
					return n
				case string:
					if x, err := strconv.Atoi(n); err == nil {
						return x
					}
				}
			}
		}
		return 0
	}
	cfg := wafowasp.BaseConfig{
		BlockingParanoia:     pickInt("blocking_paranoia_level", "blocking_paranoia"),
		DetectionParanoia:    pickInt("detection_paranoia_level", "detection_paranoia"),
		InboundThreshold:     pickInt("inbound_anomaly_score_threshold", "inbound_threshold"),
		OutboundThreshold:    pickInt("outbound_anomaly_score_threshold", "outbound_threshold"),
		EarlyBlocking:        pickInt("early_blocking"),
		EnforceBodyProcessor: pickInt("enforce_bodyproc_urlencoded", "enforce_body_processor"),
	}
	if cfg.BlockingParanoia < 1 || cfg.BlockingParanoia > 4 {
		response.FailWithMessage("blocking_paranoia_level 必须在 1..4", c)
		return
	}
	if cfg.DetectionParanoia < cfg.BlockingParanoia || cfg.DetectionParanoia > 4 {
		response.FailWithMessage("detection_paranoia_level 必须 >= blocking_paranoia_level 且 <= 4", c)
		return
	}
	if cfg.InboundThreshold <= 0 {
		cfg.InboundThreshold = 7
	}
	if cfg.OutboundThreshold <= 0 {
		cfg.OutboundThreshold = 4
	}
	if err := m.ApplyBaseConfig(cfg); err != nil {
		response.FailWithMessage("应用失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("Layer 1 基线已更新并热重载", c)
}

// TuningGetApi 获取OWASP调参配置
// @Summary      获取OWASP调参配置
// @Description  读取当前 tuning 配置，包含规则引擎模式、偏执级别、异常分阈值等完整调参项
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/tuning [get]
func (w *WafOwaspApi) TuningGetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	t, err := m.Overrides().GetTuning()
	if err != nil {
		response.FailWithMessage("读取失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(t, "获取成功", c)
}

// TuningSetApi 更新OWASP调参配置
// @Summary      更新OWASP调参配置
// @Description  写入 tuning 配置并热重载；同时兼容长名（inbound_anomaly_score_threshold）和短名（inbound_threshold）两套 key
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      object  true  "调参配置（rule_engine、blocking_paranoia_level、detection_paranoia_level、inbound_anomaly_score_threshold 等）"
// @Success      200   {object}  response.Response  "已生效（已热重载）"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/tuning [post]
func (w *WafOwaspApi) TuningSetApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	raw := map[string]interface{}{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	pickInt := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := raw[k]; ok && v != nil {
				switch n := v.(type) {
				case float64:
					return int(n)
				case int:
					return n
				case string:
					if x, err := strconv.Atoi(n); err == nil {
						return x
					}
				}
			}
		}
		return 0
	}
	pickStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	req := wafowasp.TuningConfig{
		BlockingParanoia:     pickInt("blocking_paranoia_level", "blocking_paranoia"),
		DetectionParanoia:    pickInt("detection_paranoia_level", "detection_paranoia"),
		InboundThreshold:     pickInt("inbound_anomaly_score_threshold", "inbound_threshold"),
		OutboundThreshold:    pickInt("outbound_anomaly_score_threshold", "outbound_threshold"),
		RuleEngine:           pickStr("rule_engine"),
		EarlyBlocking:        pickInt("early_blocking"),
		EnforceBodyProcessor: pickInt("enforce_bodyproc_urlencoded", "enforce_body_processor"),
	}
	if req.BlockingParanoia < 1 || req.BlockingParanoia > 4 {
		response.FailWithMessage("blocking_paranoia_level 必须在 1..4", c)
		return
	}
	if req.DetectionParanoia < req.BlockingParanoia || req.DetectionParanoia > 4 {
		response.FailWithMessage("detection_paranoia_level 必须 >= blocking_paranoia_level 且 <= 4", c)
		return
	}
	if req.InboundThreshold <= 0 {
		req.InboundThreshold = 7
	}
	if req.OutboundThreshold <= 0 {
		req.OutboundThreshold = 4
	}
	switch req.RuleEngine {
	case "On", "DetectionOnly", "Off":
	case "":
		req.RuleEngine = "On"
	default:
		response.FailWithMessage("rule_engine 取值应为 On/DetectionOnly/Off", c)
		return
	}

	if err := m.ApplyTuning(req); err != nil {
		response.FailWithMessage("应用失败: "+err.Error(), c)
		return
	}
	global.GCONFIG_OWASP_MODE = req.RuleEngine
	global.GCONFIG_OWASP_BLOCK_THRESHOLD = int64(req.InboundThreshold)
	response.OkWithMessage("已生效（已热重载）", c)
}

// ReloadApi 手动触发WAF热重载
// @Summary      手动触发WAF热重载
// @Description  清空规则扫描缓存并重新加载 WAF 配置，使所有 override 变更立即生效
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "reload 成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/reload [post]
func (w *WafOwaspApi) ReloadApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	wafowasp.InvalidateRuleCache()
	if err := m.Reload(); err != nil {
		response.FailWithMessage("reload 失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("reload 成功", c)
}

// FilesListApi 获取OWASP规则文件列表
// @Summary      获取OWASP规则文件列表
// @Description  列出 data/owasp 目录下所有规则文件及其规则条数和最后修改时间（只读参考）
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/files [get]
func (w *WafOwaspApi) FilesListApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	files, err := wafowasp.ScanAllRules(m.OwaspRoot())
	if err != nil {
		response.FailWithMessage("扫描失败: "+err.Error(), c)
		return
	}
	type fileSum struct {
		File      string `json:"file"`
		RuleCount int    `json:"rule_count"`
		ModTime   int64  `json:"mtime"`
	}
	out := make([]fileSum, 0, len(files))
	for _, f := range files {
		out = append(out, fileSum{File: f.File, RuleCount: len(f.Rules), ModTime: f.ModTime})
	}
	response.OkWithDetailed(out, "获取成功", c)
}

// FileContentApi 获取OWASP规则文件原始内容
// @Summary      获取OWASP规则文件原始内容
// @Description  返回 data/owasp 目录下指定 .conf 文件的原始文本内容，路径不允许包含 .. 以防越界
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        path  query     string  true  "相对于 owasp 根目录的文件路径"
// @Success      200   {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/file_content [get]
func (w *WafOwaspApi) FileContentApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	rel := c.Query("path")
	if rel == "" {
		response.FailWithMessage("path 不能为空", c)
		return
	}
	if strings.Contains(rel, "..") {
		response.FailWithMessage("非法路径", c)
		return
	}
	abs := filepath.Join(m.OwaspRoot(), filepath.FromSlash(rel))
	cleanRoot, _ := filepath.Abs(m.OwaspRoot())
	cleanAbs, _ := filepath.Abs(abs)
	if !strings.HasPrefix(cleanAbs, cleanRoot) {
		response.FailWithMessage("路径越界", c)
		return
	}
	data, err := os.ReadFile(cleanAbs)
	if err != nil {
		response.FailWithMessage("读取失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{"path": rel, "content": string(data)}, "获取成功", c)
}

// TestDryRunApi OWASP沙盒测试
// @Summary      OWASP沙盒测试
// @Description  模拟一次 HTTP 请求，返回命中的规则列表、累计 anomaly 分值及是否被拦截，不影响真实流量
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafOwaspDryRunReq  true  "模拟请求参数"
// @Success      200   {object}  response.Response  "测试完成"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/test/dry_run [post]
func (w *WafOwaspApi) TestDryRunApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	inst := m.Current()
	if inst == nil || inst.WAF == nil {
		response.FailWithMessage("WAF 实例未就绪", c)
		return
	}

	var req request.WafOwaspDryRunReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URL == "" {
		req.URL = "/"
	}
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		response.FailWithMessage("url 不合法: "+err.Error(), c)
		return
	}

	tx := inst.WAF.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 80)
	tx.ProcessURI(parsedURL.RequestURI(), req.Method, "HTTP/1.1")
	for k, v := range req.Headers {
		tx.AddRequestHeader(k, v)
	}
	if parsedURL.Host != "" {
		tx.AddRequestHeader("Host", parsedURL.Host)
	}

	message := "未拦截"
	if it := tx.ProcessRequestHeaders(); it != nil {
		message = "规则头阶段拦截"
		response.OkWithDetailed(buildDryRunResp(tx, it), message, c)
		return
	}
	if req.Body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(req.Body)); err != nil {
			response.FailWithMessage("写入 body 失败: "+err.Error(), c)
			return
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		response.FailWithMessage("处理 body 失败: "+err.Error(), c)
		return
	} else if it != nil {
		resp := buildDryRunResp(tx, it)
		fillTuningMeta(m, &resp)
		response.OkWithDetailed(resp, "规则体阶段拦截", c)
		return
	}

	resp := buildDryRunResp(tx, tx.Interruption())
	fillTuningMeta(m, &resp)
	response.OkWithDetailed(resp, message, c)
}

// UpdateCheckApi 检查OWASP规则库是否有新版本
// @Summary      检查OWASP规则库是否有新版本
// @Description  查询远端规则库的最新版本信息并与本地版本对比，未配置远端时返回当前版本
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/update/check [get]
func (w *WafOwaspApi) UpdateCheckApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	info, err := wafowasp.CheckUpgrade(m)
	if err != nil {
		response.FailWithMessage("检查升级失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(info, "获取成功", c)
}

// UpdateApplyApi 执行OWASP规则库升级
// @Summary      执行OWASP规则库升级
// @Description  后台异步执行规则库升级，接口立即返回；升级结果通过 WebSocket 消息推送给前端
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "升级已触发，结果将通过后台消息推送"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/update/apply [post]
func (w *WafOwaspApi) UpdateApplyApi(c *gin.Context) {
	m := w.manager(c)
	if m == nil {
		return
	}
	go func() {
		if err := wafowasp.ApplyUpgrade(m); err != nil {
			// 失败信息写入内部队列，由前端通过 WS 获取
			wafowasp.NotifyUpgradeResult(false, err.Error())
			return
		}
		wafowasp.NotifyUpgradeResult(true, "升级完成并已热重载")
	}()
	response.OkWithMessage("升级已触发，结果将通过后台消息推送", c)
}

// UsageDocApi 获取OWASP规则管理使用说明
// @Summary      获取OWASP规则管理使用说明
// @Description  返回 OWASP 规则管理功能的 Markdown 格式使用说明文档
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/usage/doc [get]
func (w *WafOwaspApi) UsageDocApi(c *gin.Context) {
	content := wafowasp.UsageDocMarkdown()
	response.OkWithDetailed(gin.H{"content": content}, "获取成功", c)
}

// HitStatsApi 获取OWASP规则命中统计
// @Summary      获取OWASP规则命中统计
// @Description  返回运行期间规则命中 Top-N 统计（内存数据，重启清零），支持按总次数、拦截次数、检测次数排序
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Param        limit  query     int     false  "最多返回条数，默认50，最大500"
// @Param        mode   query     string  false  "排序维度：all（默认，按总次数）/ blocked / detected"
// @Success      200    {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/hit_stats [get]
func (w *WafOwaspApi) HitStatsApi(c *gin.Context) {
	limit := 50
	if v, err := strconv.Atoi(c.DefaultQuery("limit", "50")); err == nil && v > 0 {
		limit = v
	}
	if limit > 500 {
		limit = 500
	}
	mode := c.DefaultQuery("mode", "all")

	list := wafowasp.GlobalHitStats.TopN(limit, mode)
	response.OkWithDetailed(gin.H{
		"list":       list,
		"rule_count": wafowasp.GlobalHitStats.TotalRuleCount(),
	}, "获取成功", c)
}

// HitStatsResetApi 清空OWASP规则命中统计
// @Summary      清空OWASP规则命中统计
// @Description  清空内存中所有规则的命中计数，重启后自动清零无需手动调用
// @Tags         OWASP规则管理
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "命中统计已清空"
// @Security     ApiKeyAuth
// @Router       /api/v1/owasp/hit_stats/reset [post]
func (w *WafOwaspApi) HitStatsResetApi(c *gin.Context) {
	wafowasp.GlobalHitStats.Reset()
	response.OkWithMessage("命中统计已清空", c)
}

// extractParanoiaFromTags 从 CRS 规则 tags 里解析 paranoia 级别。
// CRS 里的 paranoia 以 tag 形式标注，格式为 "paranoia-level/1" ~ "paranoia-level/4"。
// 未找到时返回 0，表示该规则在任意 PL 下都生效（如 initialization / evaluation 类规则）。
func extractParanoiaFromTags(tags []string) int {
	const prefix = "paranoia-level/"
	for _, t := range tags {
		if strings.HasPrefix(t, prefix) {
			if v, err := strconv.Atoi(t[len(prefix):]); err == nil {
				return v
			}
		}
	}
	return 0
}

// fillTuningMeta 把当前 tuning 的阈值与 PL 写入响应，便于前端做"命中但分不够"诊断提示。
func fillTuningMeta(m *wafowasp.OwaspManager, resp *response2.WafOwaspDryRunResp) {
	if m == nil || m.Overrides() == nil {
		return
	}
	t, err := m.Overrides().GetTuning()
	if err != nil {
		return
	}
	resp.BlockingThreshold = t.InboundThreshold
	resp.BlockingParanoia = t.BlockingParanoia
	resp.DetectionParanoia = t.DetectionParanoia
}

// buildDryRunResp 从 coraza transaction 聚合命中结果。
func buildDryRunResp(tx types.Transaction, it *types.Interruption) response2.WafOwaspDryRunResp {
	resp := response2.WafOwaspDryRunResp{}
	if it != nil {
		resp.Interrupted = true
		resp.InterruptID = it.RuleID
		resp.InterruptData = it.Data
	}
	for _, mr := range tx.MatchedRules() {
		if mr.Message() == "" {
			continue
		}
		rm := mr.Rule()
		hit := response2.WafOwaspDryRunHit{
			ID:      rm.ID(),
			Message: mr.Message(),
			Phase:   int(rm.Phase()),
			File:    rm.File(),
			Tags:    rm.Tags(),
		}
		sev := rm.Severity()
		hit.Severity = sev.String()
		hit.Paranoia = extractParanoiaFromTags(hit.Tags)
		resp.Hits = append(resp.Hits, hit)
	}
	// 读取 anomaly_score。
	// CRS 4.x：真正用于拦截判定的是 tx.blocking_inbound_anomaly_score（phase 2 末尾判定）。
	//          detection_inbound_anomaly_score 是包含观察模式(PL > blocking PL)命中的总分。
	// CRS 3.x：使用 tx.anomaly_score。
	// 注：tx.anomaly_score 是由 RESPONSE-980 phase:5 才聚合的，沙盒里因为没有响应体，所以可能一直是 0。
	if txState, ok := tx.(plugintypes.TransactionState); ok {
		txCol := txState.Variables().TX()
		readInt := func(key string) int {
			if vals := txCol.Get(key); len(vals) > 0 {
				if v, err := strconv.Atoi(vals[0]); err == nil {
					return v
				}
			}
			return 0
		}
		// 按优先级取 blocking 分。
		for _, key := range []string{
			"blocking_inbound_anomaly_score",
			"anomaly_score",
			"inbound_anomaly_score",
		} {
			if v := readInt(key); v > resp.AnomalyScore {
				resp.AnomalyScore = v
			}
		}
		resp.DetectionScore = readInt("detection_inbound_anomaly_score")
		// 兜底：若上述都为 0，尝试从 per-PL 累加器相加（某些极少数场景 blocking_inbound_anomaly_score 未被汇总）。
		if resp.AnomalyScore == 0 {
			sum := 0
			for i := 1; i <= 4; i++ {
				sum += readInt("inbound_anomaly_score_pl" + strconv.Itoa(i))
			}
			resp.AnomalyScore = sum
		}
	}
	return resp
}
