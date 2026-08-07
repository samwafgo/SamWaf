package wafhostguard

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/wafenginecore/ipset"
	"net"
	"strings"
	"sync"
	"time"
)

// 白名单是这个功能里最重要的一段代码：判错了不是漏封一个攻击者，
// 而是把管理员自己锁在服务器外面。所以做了六层，任意一层命中即豁免。

// 常见内网段。爆破防护面向的是公网攻击者，内网里的失败登录绝大多数是
// 自己人敲错密码、跳板机、内部监控探活。
var lanCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16", // 链路本地
	"100.64.0.0/10",  // 运营商级 NAT / Tailscale 等
	"fc00::/7",       // IPv6 唯一本地地址
	"fe80::/10",      // IPv6 链路本地
}

// 环回永远豁免，不受任何开关控制
var loopbackCIDRs = []string{"127.0.0.0/8", "::1/128"}

// 白名单命中原因，直接展示给用户(白名单自测工具会显示这个)
const (
	WhiteReasonLoopback = "环回地址"
	WhiteReasonLocal    = "本机网卡IP"
	WhiteReasonLAN      = "内网段自动豁免"
	WhiteReasonConfig   = "用户配置白名单"
	WhiteReasonManage   = "管理端IP白名单"
	WhiteReasonAdminIP  = "当前活跃的管理会话IP"
)

type whitelistSnapshot struct {
	loopback *ipset.MatchSet
	local    *ipset.MatchSet
	lan      *ipset.MatchSet
	config   *ipset.MatchSet
	manage   *ipset.MatchSet
	builtAt  time.Time
}

var (
	whitelistMu  sync.RWMutex
	whitelistCur *whitelistSnapshot
	whitelistTTL = 5 * time.Minute
)

// InvalidateWhitelist 丢弃当前白名单快照，下次判定时重建。
// 用户在页面上改完白名单必须立刻生效——等 5 分钟 TTL 自然过期是不可接受的，
// 因为用户改白名单往往正是因为"我被误封了"。
func InvalidateWhitelist() {
	whitelistMu.Lock()
	whitelistCur = nil
	whitelistMu.Unlock()
	InvalidateLocalAddrs()
}

// getWhitelist 取当前快照，过期则重建
func getWhitelist() *whitelistSnapshot {
	whitelistMu.RLock()
	if whitelistCur != nil && time.Since(whitelistCur.builtAt) < whitelistTTL {
		snap := whitelistCur
		whitelistMu.RUnlock()
		return snap
	}
	whitelistMu.RUnlock()

	whitelistMu.Lock()
	defer whitelistMu.Unlock()
	if whitelistCur != nil && time.Since(whitelistCur.builtAt) < whitelistTTL {
		return whitelistCur
	}

	snap := &whitelistSnapshot{
		loopback: ipset.BuildMatchSet(loopbackCIDRs),
		local:    ipset.BuildMatchSet(LocalAddrs()),
		lan:      ipset.BuildMatchSet(lanCIDRs),
		config:   ipset.BuildMatchSet(splitList(global.GCONFIG_HOST_GUARD_WHITELIST)),
		manage:   ipset.BuildMatchSet(dropCatchAll(splitList(global.GWAF_IP_WHITELIST))),
		builtAt:  time.Now(),
	}
	whitelistCur = snap
	return snap
}

// IsWhitelisted 判断 IP 是否豁免，返回命中的原因(供日志与自测工具展示)。
// 顺序即优先级，越靠前越"不可能是攻击者"。
func IsWhitelisted(ip string) (bool, string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// 解析不出来的东西不该走到封禁流程，这里当豁免处理是保守选择
		return true, "IP格式非法"
	}

	snap := getWhitelist()
	if snap.loopback.Contains(parsed) {
		return true, WhiteReasonLoopback
	}
	if snap.local.Contains(parsed) {
		return true, WhiteReasonLocal
	}
	if global.GCONFIG_HOST_GUARD_AUTO_LAN == 1 && snap.lan.Contains(parsed) {
		return true, WhiteReasonLAN
	}
	if snap.config.Contains(parsed) {
		return true, WhiteReasonConfig
	}
	if snap.manage.Contains(parsed) {
		return true, WhiteReasonManage
	}
	if isActiveAdminIP(ip) {
		return true, WhiteReasonAdminIP
	}
	return false, ""
}

// adminIPTTL 活跃管理会话 IP 的记忆时长
const adminIPTTL = 30 * time.Minute

// TouchAdminIP 记录一个正在使用管理端的客户端 IP。
//
// 这是防误封的最后一道保险，也是最实用的一道：只要你还在用管理端，
// 你的出口 IP 就永远进不了封禁名单——哪怕白名单一个字都没配。
// 由 middleware 在认证通过后调用，O(1) 写缓存。
func TouchAdminIP(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" || global.GCACHE_WAFCACHE == nil {
		return
	}
	if net.ParseIP(ip) == nil {
		return
	}
	global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_HOST_GUARD_ADMIN_PRE+ip, 1, adminIPTTL)
}

// isActiveAdminIP 该 IP 最近是否用过管理端
func isActiveAdminIP(ip string) bool {
	if global.GCACHE_WAFCACHE == nil {
		return false
	}
	return global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_HOST_GUARD_ADMIN_PRE + ip)
}

// dropCatchAll 剔除覆盖全网的条目(0.0.0.0/0、::/0 等前缀长度为 0 的 CIDR)。
//
// 必须做这一步：管理端 IP 白名单 GWAF_IP_WHITELIST 的默认值就是 "0.0.0.0/0,::/0"
// (后台默认放行所有来源)。原样拿来当豁免层，默认配置下每个 IP 都会命中白名单，
// 防爆破就成了摆设。只有用户真的收窄过管理端白名单，这一层才有意义。
func dropCatchAll(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ipNet, err := net.ParseCIDR(item); err == nil {
			if ones, _ := ipNet.Mask.Size(); ones == 0 {
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

// splitList 拆逗号分隔配置，去空白与空项
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
