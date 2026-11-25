package api

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/iplocation"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/idna"
	"gorm.io/gorm"
)

var tunnelChangeMu sync.Mutex

func validateTunnelRegion(req *request.WafTunnelRegionProtectionReq) error {
	codes := iplocation.CountryCodes()
	for i := range req.Rules {
		rule := &req.Rules[i]
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Country = strings.ToUpper(strings.TrimSpace(rule.Country))
		if rule.Name == "" || !utf8.ValidString(rule.Name) || utf8.RuneCountInString(rule.Name) > 60 || strings.ContainsFunc(rule.Name, unicode.IsControl) {
			return fmt.Errorf("第 %d 条地区规则名称须为 1–60 个非控制字符", i+1)
		}
		if _, found := slices.BinarySearch(codes, rule.Country); !found || (rule.Operator != "eq" && rule.Operator != "ne") || (rule.Action != "allow" && rule.Action != "deny") {
			return fmt.Errorf("第 %d 条地区规则的国家、条件或动作不合法", i+1)
		}
	}
	return nil
}

func normalizeTunnelDDNSDomain(raw string) (string, error) {
	invalid := errors.New("请输入完整域名，不能包含 IP、端口、通配符或 URL")
	if len(raw) > 1024 || !utf8.ValidString(raw) {
		return "", invalid
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSpace(raw))
	if err != nil {
		return "", invalid
	}
	domain := strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", invalid
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return "", invalid
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return "", invalid
			}
		}
	}
	if !strings.ContainsFunc(labels[len(labels)-1], func(char rune) bool { return char >= 'a' && char <= 'z' }) {
		return "", invalid
	}
	return domain, nil
}

func validateTunnelDDNS(req *request.WafTunnelDDNSProtectionReq) error {
	domains := make(map[string]bool, len(req.Bindings))
	ids := make(map[string]bool, len(req.Bindings))
	for i := range req.Bindings {
		binding := &req.Bindings[i]
		domain, err := normalizeTunnelDDNSDomain(binding.Domain)
		if err != nil {
			return fmt.Errorf("第 %d 条绑定：%w", i+1, err)
		}
		if domains[domain] || (binding.ID != "" && ids[binding.ID]) || len(binding.ID) > 64 {
			return fmt.Errorf("第 %d 条绑定重复或标识不合法", i+1)
		}
		if binding.Family != "ipv4" && binding.Family != "ipv6" && binding.Family != "both" {
			return fmt.Errorf("第 %d 条绑定的地址族不合法", i+1)
		}
		binding.Domain = domain
		domains[domain] = true
		ids[binding.ID] = true
	}
	return nil
}

func tunnelProtectionError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		response.FailWithMessage("隧道不存在", c)
	case errors.Is(err, waf_service.ErrTunnelProtectionConflict), errors.Is(err, waf_service.ErrTunnelWhitelistConfirm), errors.Is(err, waf_service.ErrTunnelDDNSBinding):
		response.FailWithMessage(err.Error(), c)
	default:
		zlog.Error("隧道访问防护配置操作失败")
		response.FailWithMessage("隧道访问防护配置操作失败，请稍后重试", c)
	}
}

func tunnelDDNSStatuses(config waf_service.TunnelProtectionConfig) []model.TunnelDDNSStatus {
	var runtime []model.TunnelDDNSStatus
	if engine := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE; engine != nil {
		runtime = engine.DDNSStatuses(config.Tunnel.Id, config.DDNS.Revision)
	}
	states := make([]model.TunnelDDNSStatus, 0, len(config.DDNS.Bindings))
	for _, binding := range config.DDNS.Bindings {
		status := model.TunnelDDNSStatus{BindingID: binding.ID, State: "pending", IPs: []string{}}
		if !binding.Enabled {
			status.State = "disabled"
		} else if i := slices.IndexFunc(runtime, func(row model.TunnelDDNSStatus) bool { return row.BindingID == binding.ID }); i >= 0 {
			status = runtime[i]
			if status.IPs == nil {
				status.IPs = []string{}
			}
		}
		states = append(states, status)
	}
	return states
}

func (w *WafTunnelApi) GetProtectionApi(c *gin.Context) {
	var req request.WafTunnelProtectionDetailReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("隧道标识不合法", c)
		return
	}
	config, err := wafTunnelService.GetProtection(c.Request.Context(), req.ID)
	if err != nil {
		tunnelProtectionError(c, err)
		return
	}
	ipv4, ipv6 := global.GIPLOCATION_MANAGER.CountryAvailability()
	role := enums.NormalizeRole(c.GetString("userRole"))
	response.OkWithDetailed(gin.H{
		"region": config.Region, "ddns": config.DDNS, "states": tunnelDDNSStatuses(config),
		"countries": iplocation.CountryCodes(), "ipv4_country_available": ipv4, "ipv6_country_available": ipv6,
		"allow_ip": config.Tunnel.AllowIp, "deny_ip": config.Tunnel.DenyIp,
		"allowed_time_ranges": config.Tunnel.AllowedTimeRanges,
		"whitelist_active": config.Tunnel.AllowIp != "" || waf_service.HasEnabledTunnelDDNS(config.DDNS.Bindings),
		"can_view_audit":   role == enums.ROLE_SUPER_ADMIN || role == enums.ROLE_AUDIT_ADMIN,
	}, "获取成功", c)
}

func bindTunnelProtection(c *gin.Context, req any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	if err := c.ShouldBindJSON(req); err != nil {
		response.FailWithMessage("隧道访问防护参数不合法", c)
		return false
	}
	return true
}

func notifyTunnelProtection(before, after model.Tunnel) {
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type: enums.ChanComTypeTunnel, OpType: enums.OP_TYPE_UPDATE, OldContent: before, Content: after,
	}
}

func auditTunnelProtection(c *gin.Context, tunnel model.Tunnel, event, reason string, before, after *waf_service.TunnelAuditState) {
	waf_service.WafSecurityAuditServiceApp.WriteTunnelConfig(c.GetString("loginAccount"), utils.GetManageClientIP(c), tunnel, event, reason, before, after)
}

func (w *WafTunnelApi) SaveRegionProtectionApi(c *gin.Context) {
	var req request.WafTunnelRegionProtectionReq
	if !bindTunnelProtection(c, &req) {
		return
	}
	if err := validateTunnelRegion(&req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	next := model.TunnelRegionProtection{Revision: req.Revision, Enabled: *req.Enabled, Fallback: req.Fallback, Unknown: req.Unknown, Rules: req.Rules}
	tunnelChangeMu.Lock()
	defer tunnelChangeMu.Unlock()
	before, after, err := wafTunnelService.SaveRegionProtection(c.Request.Context(), req.ID, next)
	if err != nil {
		tunnelProtectionError(c, err)
		return
	}
	if before.Region.Revision != after.Region.Revision {
		notifyTunnelProtection(before.Tunnel, after.Tunnel)
		auditTunnelProtection(c, after.Tunnel, model.AuditEventConfigTunnelRegion, "edit", &waf_service.TunnelAuditState{Region: &before.Region}, &waf_service.TunnelAuditState{Region: &after.Region})
	}
	response.OkWithDetailed(after.Region, "保存成功", c)
}

func tunnelBindingAuditState(binding model.TunnelDDNSBinding, ips []string) *waf_service.TunnelAuditState {
	return &waf_service.TunnelAuditState{Hostname: binding.Domain, BindingID: binding.ID, Family: binding.Family, Enabled: binding.Enabled, Addresses: ips}
}

func auditTunnelBindingChanges(c *gin.Context, tunnel model.Tunnel, before, after []model.TunnelDDNSBinding, states []model.TunnelDDNSStatus) {
	ips := make(map[string][]string, len(states))
	for _, state := range states {
		ips[state.BindingID] = state.IPs
	}
	for _, binding := range before {
		oldState := tunnelBindingAuditState(binding, ips[binding.ID])
		i := slices.IndexFunc(after, func(row model.TunnelDDNSBinding) bool { return row.ID == binding.ID })
		if i < 0 {
			auditTunnelProtection(c, tunnel, model.AuditEventConfigTunnelDDNS, "delete", oldState, nil)
		} else if after[i] != binding {
			auditTunnelProtection(c, tunnel, model.AuditEventConfigTunnelDDNS, "edit", oldState, tunnelBindingAuditState(after[i], nil))
		}
	}
	for _, binding := range after {
		if !slices.ContainsFunc(before, func(row model.TunnelDDNSBinding) bool { return row.ID == binding.ID }) {
			auditTunnelProtection(c, tunnel, model.AuditEventConfigTunnelDDNS, "add", nil, tunnelBindingAuditState(binding, nil))
		}
	}
}

func (w *WafTunnelApi) SaveDDNSProtectionApi(c *gin.Context) {
	var req request.WafTunnelDDNSProtectionReq
	if !bindTunnelProtection(c, &req) {
		return
	}
	if err := validateTunnelDDNS(&req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	tunnelChangeMu.Lock()
	defer tunnelChangeMu.Unlock()
	next := model.TunnelDDNSProtection{Revision: req.Revision, Bindings: req.Bindings}
	before, after, err := wafTunnelService.SaveDDNSProtection(c.Request.Context(), req.ID, next, req.ConfirmDisableWhitelist)
	if err != nil {
		tunnelProtectionError(c, err)
		return
	}
	if before.DDNS.Revision != after.DDNS.Revision {
		states := tunnelDDNSStatuses(before)
		notifyTunnelProtection(before.Tunnel, after.Tunnel)
		auditTunnelBindingChanges(c, after.Tunnel, before.DDNS.Bindings, after.DDNS.Bindings, states)
	}
	response.OkWithDetailed(after.DDNS, "保存成功", c)
}

func (w *WafTunnelApi) RefreshDDNSProtectionApi(c *gin.Context) {
	var req request.WafTunnelDDNSRefreshReq
	if !bindTunnelProtection(c, &req) {
		return
	}
	config, err := wafTunnelService.GetProtection(c.Request.Context(), req.ID)
	if err != nil {
		tunnelProtectionError(c, err)
		return
	}
	i := slices.IndexFunc(config.DDNS.Bindings, func(row model.TunnelDDNSBinding) bool { return row.ID == req.BindingID && row.Enabled })
	if i < 0 {
		response.FailWithMessage("绑定不存在或未启用", c)
		return
	}
	engine := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE
	if engine == nil {
		response.FailWithMessage("隧道服务尚未就绪", c)
		return
	}
	if err := engine.RefreshDDNS(req.ID, req.BindingID, config.DDNS.Revision); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	auditTunnelProtection(c, config.Tunnel, model.AuditEventConfigTunnelDDNS, "manual_refresh", nil, tunnelBindingAuditState(config.DDNS.Bindings[i], nil))
	response.OkWithMessage("已提交解析，请稍后刷新状态", c)
}
