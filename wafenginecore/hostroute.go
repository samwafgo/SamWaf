package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"strconv"
)

// clearHostRoutes 按站点指针摘掉该 code 占用的全部路由 key。
// 禁止按「域名字符串」盲删，否则删 B 会把 A 仍在用的 HostTarget / NoPort 一并清掉。
func clearHostRoutes(nt *routingTable, code string) {
	if code == "" || nt == nil {
		return
	}
	delete(nt.HostCode, code)
	var oldHS *wafenginmodel.HostSafe
	if oldKey, ok := nt.HostCode[code]; ok {
		oldHS = nt.HostTarget[oldKey]
	}
	if oldHS == nil {
		for _, v := range nt.HostTarget {
			if v != nil && v.Host.Code == code {
				oldHS = v
				break
			}
		}
	}
	if oldHS != nil {
		owned := map[string]struct{}{}
		for k, v := range nt.HostTarget {
			if v == oldHS {
				owned[k] = struct{}{}
			}
		}
		for k, v := range nt.HostTargetNoPort {
			if _, ok := owned[v]; ok {
				delete(nt.HostTargetNoPort, k)
			}
		}
		for k := range owned {
			delete(nt.HostTarget, k)
		}
	}
	for k, v := range nt.HostTargetMoreDomain {
		if v == code {
			delete(nt.HostTargetMoreDomain, k)
		}
	}
}

func takeHostTarget(nt *routingTable, key string, hostsafe *wafenginmodel.HostSafe) bool {
	if key == "" || hostsafe == nil {
		return false
	}
	if existing, ok := nt.HostTarget[key]; ok && existing != nil && existing.Host.Code != hostsafe.Host.Code {
		zlog.Warn("域名路由冲突：key 已被其它站点占用，先到先得",
			"key", key, "want", hostsafe.Host.Code, "owner", existing.Host.Code)
		return false
	}
	nt.HostTarget[key] = hostsafe
	return true
}

func takeMoreDomain(nt *routingTable, key, code string) {
	if key == "" || code == "" {
		return
	}
	if existing, ok := nt.HostTarget[key]; ok && existing != nil && existing.Host.Code != code {
		zlog.Warn("域名路由冲突：BindMoreHost key 已是其它站主域名，跳过",
			"key", key, "want", code, "owner", existing.Host.Code)
		return
	}
	if existing, ok := nt.HostTargetMoreDomain[key]; ok && existing != "" && existing != code {
		zlog.Warn("域名路由冲突：BindMoreHost key 已被其它站点占用，先到先得",
			"key", key, "want", code, "owner", existing)
		return
	}
	nt.HostTargetMoreDomain[key] = code
}

func takeNoPort(nt *routingTable, domain, ourTarget string, hostsafe *wafenginmodel.HostSafe) {
	if domain == "" || ourTarget == "" || hostsafe == nil {
		return
	}
	if existing, ok := nt.HostTargetNoPort[domain]; ok && existing != ourTarget {
		if hs := nt.HostTarget[existing]; hs != nil && hs.Host.Code != hostsafe.Host.Code {
			zlog.Warn("域名路由冲突：宽松端口映射已被其它站点占用，先到先得",
				"domain", domain, "want", hostsafe.Host.Code, "owner", hs.Host.Code)
			return
		}
	}
	nt.HostTargetNoPort[domain] = ourTarget
}

// applyHostRouteMaps 把站点写入路由快照（key 一律 CanonicalHost）。
func applyHostRouteMaps(nt *routingTable, inHost model.Hosts, hostsafe *wafenginmodel.HostSafe) {
	canonMain := utils.CanonicalHost(inHost.Host)
	if canonMain == "" {
		zlog.Warn("站点主域名为空，跳过路由注册", "code", inHost.Code)
		return
	}
	extra := utils.HostRoutedExtraPorts(inHost)
	names := utils.HostNames(inHost)
	mainKey := canonMain + ":" + strconv.Itoa(inHost.Port)
	hasRoute := false
	if takeHostTarget(nt, mainKey, hostsafe) {
		nt.HostCode[inHost.Code] = mainKey
		hasRoute = true
	}

	for _, p := range extra {
		if takeHostTarget(nt, canonMain+":"+strconv.Itoa(p), hostsafe) {
			hasRoute = true
		}
	}

	if inHost.AutoJumpHTTPS == 1 {
		k80 := canonMain + ":80"
		if takeHostTarget(nt, k80, hostsafe) {
			nt.HostCode[inHost.Code] = k80
			hasRoute = true
		}
	}
	if !hasRoute {
		return
	}

	ourTarget := mainKey
	if inHost.UnrestrictedPort == 1 {
		for _, d := range names {
			takeNoPort(nt, d, ourTarget, hostsafe)
		}
	}

	for _, d := range names {
		if d == canonMain {
			continue
		}
		takeMoreDomain(nt, d+":"+strconv.Itoa(inHost.Port), inHost.Code)
		for _, p := range extra {
			takeMoreDomain(nt, d+":"+strconv.Itoa(p), inHost.Code)
		}
		if inHost.AutoJumpHTTPS == 1 {
			takeMoreDomain(nt, d+":80", inHost.Code)
		}
	}
}

func routeKeyDomain(key string) string {
	h, _, hasPort := utils.SplitHostPortLoose(key)
	if hasPort {
		return utils.CanonicalHost(h)
	}
	return utils.CanonicalHost(key)
}

// routeLookupCandidates 与 ServeHTTP 同一套域名归一：纯域名 + 待查的 host:port 列表。
// 未带端口时 80/443 都试（无 TLS 上下文的反查）。
func routeLookupCandidates(hostWithPort string) (pure string, keys []string) {
	h, p, hasPort := utils.SplitHostPortLoose(hostWithPort)
	if !hasPort {
		pure = utils.CanonicalHost(hostWithPort)
		return pure, []string{pure + ":443", pure + ":80"}
	}
	pure = utils.CanonicalHost(h)
	return pure, []string{pure + ":" + p}
}
