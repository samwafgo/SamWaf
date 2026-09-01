package utils

import (
	"SamWaf/model"
	"fmt"
	"strconv"
	"strings"
)

// RouteClaim 一个站点在路由表上会占用的「归一化域名 + 端口」。
// AnyPort 对应来源端口宽松：该域名在任意端口都算被占用。
type RouteClaim struct {
	Domain  string
	Port    int
	AnyPort bool
}

// ValidateHostNamesNoDuplicate 校验站点主域名与 BindMoreHost 在 CanonicalHost 后不得重复。
// 中文与 Punycode、大小写变体视为同一域名，保存期即拒绝冗余配置。
func ValidateHostNamesNoDuplicate(h model.Hosts) error {
	seen := map[string]string{}
	check := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		canon := CanonicalHost(raw)
		if canon == "" {
			return nil
		}
		if first, ok := seen[canon]; ok {
			return fmt.Errorf("域名 %s 与 %s 为同一域名（归一后均为 %s），请勿在同一站点重复绑定", first, raw, canon)
		}
		seen[canon] = raw
		return nil
	}
	if err := check(h.Host); err != nil {
		return err
	}
	for _, line := range SplitBindMoreHost(h.BindMoreHost) {
		if err := check(line); err != nil {
			return err
		}
	}
	return nil
}

// HostNames 站点主域名 + BindMoreHost，已 CanonicalHost 且去重。
func HostNames(h model.Hosts) []string {
	seen := map[string]bool{}
	var names []string
	add := func(raw string) {
		c := CanonicalHost(raw)
		if c == "" || seen[c] {
			return
		}
		seen[c] = true
		names = append(names, c)
	}
	add(h.Host)
	for _, line := range SplitBindMoreHost(h.BindMoreHost) {
		add(line)
	}
	return names
}

// HostRouteClaims 计算站点将会写入路由表的占用（主域名/别名 × 路由端口 / 宽松端口）。
// 全局站点不参与用户域名互斥。
func HostRouteClaims(h model.Hosts) []RouteClaim {
	if h.GLOBAL_HOST == 1 {
		return nil
	}
	names := HostNames(h)
	if len(names) == 0 {
		return nil
	}
	portSet := map[int]struct{}{}
	if h.Port >= 1 && h.Port <= 65535 {
		portSet[h.Port] = struct{}{}
	}
	for _, p := range HostRoutedExtraPorts(h) {
		if p >= 1 && p <= 65535 {
			portSet[p] = struct{}{}
		}
	}
	if h.AutoJumpHTTPS == 1 {
		portSet[80] = struct{}{}
	}

	var claims []RouteClaim
	for _, d := range names {
		if h.UnrestrictedPort == 1 {
			claims = append(claims, RouteClaim{Domain: d, AnyPort: true})
		}
		for p := range portSet {
			claims = append(claims, RouteClaim{Domain: d, Port: p})
		}
	}
	return claims
}

// ClaimsOverlap 同一归一化域名下：任一方宽松端口，或端口号相同，即冲突。
// `*` 通配站点只与同为 `*` 的声明冲突，不霸占具体域名。
func ClaimsOverlap(a, b RouteClaim) bool {
	if a.Domain == "" || b.Domain == "" || a.Domain != b.Domain {
		return false
	}
	if a.AnyPort || b.AnyPort {
		return true
	}
	return a.Port == b.Port
}

// FindRouteClaimConflict 在 all 里找与 candidate 冲突的站点（排除 excludeCode 与全局站）。
func FindRouteClaimConflict(excludeCode string, candidate model.Hosts, all []model.Hosts) (conflictWith model.Hosts, claim RouteClaim, found bool) {
	want := HostRouteClaims(candidate)
	if len(want) == 0 {
		return model.Hosts{}, RouteClaim{}, false
	}
	for _, other := range all {
		if other.GLOBAL_HOST == 1 {
			continue
		}
		if excludeCode != "" && other.Code == excludeCode {
			continue
		}
		for _, oc := range HostRouteClaims(other) {
			for _, wc := range want {
				if ClaimsOverlap(wc, oc) {
					return other, wc, true
				}
			}
		}
	}
	return model.Hosts{}, RouteClaim{}, false
}

// FormatRouteClaim 占用检查给人看的「域名:端口」片段。
func FormatRouteClaim(c RouteClaim) string {
	if c.AnyPort {
		return c.Domain + "（来源端口宽松，任意端口）"
	}
	if c.Port > 0 {
		return c.Domain + ":" + strconv.Itoa(c.Port)
	}
	return c.Domain
}
