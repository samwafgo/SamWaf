package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// matchTypeOrder 返回匹配类型的排序权重（数字越小越优先）
// 2=精确匹配 > 1=前缀匹配 > 3=正则匹配
func matchTypeOrder(t int) int {
	switch t {
	case 2:
		return 0
	case 1:
		return 1
	case 3:
		return 2
	default:
		return 3
	}
}

// MatchPathRule 在路径规则列表中找到第一条匹配 urlPath 的规则。
// 排序优先级：Priority ASC → matchTypeOrder ASC → Path 长度 DESC（更长的前缀更优先）。
// 返回第一个命中的规则，无匹配返回 nil。
func MatchPathRule(rules []model.HostPathRule, urlPath string) *model.HostPathRule {
	if len(rules) == 0 {
		return nil
	}

	sorted := make([]model.HostPathRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := sorted[i], sorted[j]
		if ri.Priority != rj.Priority {
			return ri.Priority < rj.Priority
		}
		oi, oj := matchTypeOrder(ri.MatchType), matchTypeOrder(rj.MatchType)
		if oi != oj {
			return oi < oj
		}
		return len(ri.Path) > len(rj.Path)
	})

	for i := range sorted {
		if pathRuleMatches(&sorted[i], urlPath) {
			return &sorted[i]
		}
	}
	return nil
}

// pathRuleMatches 判断单条规则是否匹配 urlPath
func pathRuleMatches(rule *model.HostPathRule, urlPath string) bool {
	switch rule.MatchType {
	case 1: // 前缀匹配
		return strings.HasPrefix(urlPath, rule.Path)
	case 2: // 精确匹配
		return urlPath == rule.Path
	case 3: // 正则匹配
		matched, err := regexp.MatchString(rule.Path, urlPath)
		if err != nil {
			return false
		}
		return matched
	}
	return false
}

// ServeStaticFiles 为静态文件类型的路径规则提供文件服务。
// 复用 static_server.go 的完整安全检查（路径穿越、敏感文件、扩展名白名单、安全响应头等）。
// 若 StripPrefix=1，则剥离请求路径中的规则前缀后再映射到 StaticRoot。
func (waf *WafEngine) ServeStaticFiles(w http.ResponseWriter, r *http.Request, rule *model.HostPathRule, weblog *innerbean.WebLog, hostsafe *wafenginmodel.HostSafe) {
	prefix := ""
	if rule.StripPrefix == 1 {
		prefix = rule.Path
	}
	cfg := hostsafe.StaticConfig // 继承主机安全配置（安全头、敏感路径、扩展名白名单等）
	cfg.IsEnableStaticSite = 1
	cfg.StaticSitePath = rule.StaticRoot
	cfg.StaticSitePrefix = prefix
	cfg.SpaFallback = rule.SpaFallback
	waf.serveStaticFile(w, r, cfg, weblog, hostsafe)
}
