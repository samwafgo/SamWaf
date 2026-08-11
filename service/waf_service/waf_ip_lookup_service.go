package waf_service

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafenginecore/ipset"
	"SamWaf/wafipban"
	"SamWaf/waftask/threatip"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// waf_ip_lookup_service 回答一个很具体的问题：这个 IP 现在到底在哪些名单里？
//
// 封禁/放行分散在七个地方(黑名单、白名单、IP组、威胁情报、IP失败封禁、CC封禁、系统防火墙)，
// 外加 CDN 回源段。排查「为什么这个 IP 被拦了 / 为什么没被拦」时，用户得挨个页面翻，
// 还得自己心算 CIDR 包不包含——这里一次查完。
//
// 判定一律用 utils.MatchIPPattern(与引擎同一套语法：单IP/CIDR/通配符/区间)，
// 不做字符串相等比较，否则 1.2.3.4 落在 1.2.3.0/24 里会被漏报。
type WafIPLookupService struct{}

var WafIPLookupServiceApp = new(WafIPLookupService)

// 大集合(威胁情报渠道、CDN回源段)编译成 CIDR trie 缓存起来，按快照 sha 失效。
//
// 不这么做的话只能逐条 utils.MatchIPPattern，十万条就是十万次调用，而共享的
// pattern 解析缓存只有 4096 条上限——一次查询就能把它塞满，于是：
//  1. 缓存满了之后每条都要重新解析，查一次要好几秒；
//  2. 更糟的是把规则引擎请求热路径在用的那份缓存给挤掉了。
//
// 编译成 trie 后单次判定是 O(1)，也完全不碰那个共享缓存。
type cachedMatcher struct {
	sha string
	set *ipset.MatchSet
}

var (
	lookupMatcherMu sync.Mutex
	threatMatchers  = map[string]*cachedMatcher{}
	cdnMatchers     = map[string]*cachedMatcher{}
)

// matcherFor 取(或重建)某个集合的编译结果。sha 变了说明快照已更新，重建。
func matcherFor(store map[string]*cachedMatcher, key, sha string, load func() []string) *ipset.MatchSet {
	lookupMatcherMu.Lock()
	defer lookupMatcherMu.Unlock()

	if c, ok := store[key]; ok && c.sha == sha && sha != "" {
		return c.set
	}
	items := load()
	if items == nil {
		return nil
	}
	set := ipset.BuildMatchSet(items)
	store[key] = &cachedMatcher{sha: sha, set: set}
	return set
}

// matchedEntryIn 命中之后再回头找出具体是哪一条规则匹配的。
// 只在确实命中时才走(命中很罕见)，且直接用 ParsePatternLenient 而不是带缓存的版本，
// 免得又把一次性条目灌进共享 pattern 缓存。
func matchedEntryIn(items []string, ip net.IP) string {
	for _, raw := range items {
		p, err := ipset.ParsePatternLenient(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if p.Match(ip) {
			return raw
		}
	}
	return ""
}

// 来源码，与前端组件的图例一一对应
const (
	srcIPBlack  = "ip_black"
	srcIPWhite  = "ip_white"
	srcIPGroup  = "ip_group"
	srcThreatIP = "threat_ip"
	// srcThreatExclude 威胁情报误报排除名单。放在结果里是为了回答"为什么它没被拦"——
	// 只报 block 不报 allow 的话，用户排除完再查会看到一片空白，分不清是不在情报里还是已豁免。
	srcThreatExclude = "threat_exclude"
	srcIPFailure     = "ip_failure"
	srcCCBan         = "cc_ban"
	srcFirewall      = "firewall"
	srcCDN           = "cdn"
)

// normalizeLookupInput 把用户输入归一成一个可查的 IP。
// 支持单IP、CIDR(取网络地址)、起-止区间(取起始)；返回的第二个值是要告诉用户的说明，
// 空表示输入本来就是单个IP、没做任何替换。
func normalizeLookupInput(raw string) (net.IP, string) {
	if ip := net.ParseIP(raw); ip != nil {
		return ip, ""
	}
	if _, ipNet, err := net.ParseCIDR(raw); err == nil && ipNet != nil {
		return ipNet.IP, fmt.Sprintf("输入的是网段 %s，已按其中的 %s 查询", raw, ipNet.IP.String())
	}
	if i := strings.Index(raw, "-"); i > 0 {
		start := strings.TrimSpace(raw[:i])
		if ip := net.ParseIP(start); ip != nil {
			return ip, fmt.Sprintf("输入的是区间 %s，已按起始的 %s 查询", raw, start)
		}
	}
	return nil, ""
}

// Lookup 查询一个 IP 的归属情况。sources 为空表示查全部来源。
func (r *WafIPLookupService) Lookup(ipStr string, sources []string) (*response2.IPLookupResp, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return nil, fmt.Errorf("请输入要查询的IP")
	}
	// 用户可能是从「查看IP」列表里点进来的，那儿是网段/区间不是单个IP。
	// 直接判非法太粗暴——取其中一个代表IP来查，并如实说明查的是哪个。
	parsed, note := normalizeLookupInput(ipStr)
	if parsed == nil {
		return nil, fmt.Errorf("不是合法的IP地址或网段：%s", ipStr)
	}
	if note != "" {
		ipStr = parsed.String()
	}

	// 空表示查全部；前端为了能显示进度会分批只查其中几个
	want := map[string]bool{}
	for _, s := range sources {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}
	all := len(want) == 0
	pick := func(src string) bool { return all || want[src] }

	resp := &response2.IPLookupResp{
		IP:        ipStr,
		QueryNote: note,
		Hits:      make([]response2.IPLookupHit, 0, 4),
		Sources:   make([]string, 0, 8),
		Degraded:  make([]string, 0),
	}
	for _, src := range []string{
		srcIPWhite, srcIPBlack, srcIPGroup, srcThreatIP,
		srcIPFailure, srcCCBan, srcFirewall, srcCDN,
	} {
		if pick(src) {
			resp.Sources = append(resp.Sources, src)
		}
	}

	// 归属地只在查名单类时带上，分批时不必每批都查一遍
	if pick(srcIPWhite) || all {
		resp.Location = r.location(ipStr)
	}

	// 名单类共用一份站点名映射，没查名单就不用捞 hosts 表
	var hostNames map[string]string
	if pick(srcIPWhite) || pick(srcIPBlack) {
		hostNames = r.hostNameMap()
	}

	// 白名单放在最前：命中白名单的 IP 即便同时在黑名单里也会被放行，
	// 顺序本身就是给用户的排查提示
	if pick(srcIPWhite) {
		r.matchAllowList(ipStr, hostNames, resp)
	}
	if pick(srcIPBlack) {
		r.matchBlockList(ipStr, hostNames, resp)
	}
	if pick(srcIPGroup) {
		r.matchIPGroup(ipStr, resp)
	}
	if pick(srcThreatIP) {
		r.matchThreatIP(ipStr, parsed, resp)
	}
	if pick(srcIPFailure) {
		r.matchIPFailure(ipStr, resp)
	}
	if pick(srcCCBan) {
		r.matchCCBan(ipStr, resp)
	}
	if pick(srcFirewall) {
		r.matchFirewall(ipStr, resp)
	}
	if pick(srcCDN) {
		r.matchCDN(ipStr, resp)
	}

	return resp, nil
}

// location 查归属地，查不到就留空——归属地只是辅助信息，不该让整个查询失败
func (r *WafIPLookupService) location(ipStr string) string {
	if global.GIPLOCATION_MANAGER == nil {
		return ""
	}
	res := global.GIPLOCATION_MANAGER.Lookup(ipStr)
	if res == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	for _, s := range []string{res.Country, res.Province, res.City, res.ISP} {
		if s = strings.TrimSpace(s); s != "" && s != "0" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// hostNameMap 网站唯一码 → 域名，用于把 host_code 翻成用户认得的名字
func (r *WafIPLookupService) hostNameMap() map[string]string {
	m := map[string]string{}
	var hosts []model.Hosts
	if err := global.GWAF_LOCAL_DB.Select("code", "host").Find(&hosts).Error; err != nil {
		return m
	}
	for _, h := range hosts {
		m[h.Code] = h.Host
	}
	return m
}

// hostLabel 把 host_code 翻成用户认得的站点名。
//
// 全局站点在 hosts 表里就是一条 host="全局网站" 的普通记录(code 是 uuid)，
// 所以走 names 就能得到「全局网站」，不需要特殊分支——
// global.GWAF_GLOBAL_HOST_CODE 那个 "0" 是引擎路由表的 key，不是数据库 code，别拿来比。
//
// 查不到对应站点说明这条名单指向了已删除(或从来不存在)的站点，实际不会生效，
// 必须标出来，不能让用户以为它在保护什么。
func (r *WafIPLookupService) hostLabel(code string, names map[string]string) string {
	if code == "" {
		return "全局"
	}
	if n, ok := names[code]; ok && n != "" {
		return n
	}
	return code + "(站点已不存在，该条不生效)"
}

func (r *WafIPLookupService) matchAllowList(ip string, names map[string]string, resp *response2.IPLookupResp) {
	var rows []model.IPAllowList
	if err := global.GWAF_LOCAL_DB.Find(&rows).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcIPWhite)
		return
	}
	for _, row := range rows {
		// IpType=group 的行本身没有 IP，内容在 IP 组里，交给 matchIPGroup 统一判
		if row.IpType == model.IPEntryTypeGroup || row.Ip == "" {
			continue
		}
		if utils.MatchIPPattern(ip, row.Ip) {
			resp.Hits = append(resp.Hits, response2.IPLookupHit{
				Source:     srcIPWhite,
				SourceName: "IP白名单",
				Scope:      r.hostLabel(row.HostCode, names),
				Matched:    row.Ip,
				Effect:     "allow",
				Detail:     row.Remarks,
			})
		}
	}
}

func (r *WafIPLookupService) matchBlockList(ip string, names map[string]string, resp *response2.IPLookupResp) {
	var rows []model.IPBlockList
	if err := global.GWAF_LOCAL_DB.Find(&rows).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcIPBlack)
		return
	}
	for _, row := range rows {
		if row.IpType == model.IPEntryTypeGroup || row.Ip == "" {
			continue
		}
		if utils.MatchIPPattern(ip, row.Ip) {
			resp.Hits = append(resp.Hits, response2.IPLookupHit{
				Source:     srcIPBlack,
				SourceName: "IP黑名单",
				Scope:      r.hostLabel(row.HostCode, names),
				Matched:    row.Ip,
				Effect:     "block",
				Detail:     row.Remarks,
			})
		}
	}
}

// matchIPGroup IP 组本身不决定放行还是拦截——取决于哪个名单引用了它，
// 所以 effect 记 none，另外把引用它的名单列出来，用户才知道命中意味着什么
func (r *WafIPLookupService) matchIPGroup(ip string, resp *response2.IPLookupResp) {
	var groups []model.IPGroup
	if err := global.GWAF_LOCAL_DB.Find(&groups).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcIPGroup)
		return
	}
	if len(groups) == 0 {
		return
	}

	// 一次把所有组条目捞出来按组分桶，避免每组一次查询
	var items []model.IPGroupItem
	if err := global.GWAF_LOCAL_DB.Find(&items).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcIPGroup)
		return
	}
	byGroup := map[string][]model.IPGroupItem{}
	for _, it := range items {
		byGroup[it.GroupCode] = append(byGroup[it.GroupCode], it)
	}

	refs := r.groupRefs()
	for _, g := range groups {
		for _, it := range byGroup[g.GroupCode] {
			if it.Ip == "" || !utils.MatchIPPattern(ip, it.Ip) {
				continue
			}
			effect := "none"
			detail := "该组未被任何黑/白名单引用"
			if ref, ok := refs[g.GroupCode]; ok {
				effect = ref.effect
				detail = ref.text
			}
			resp.Hits = append(resp.Hits, response2.IPLookupHit{
				Source:     srcIPGroup,
				SourceName: "IP组",
				Scope:      g.GroupName,
				Matched:    it.Ip,
				Effect:     effect,
				Detail:     detail,
			})
			break // 同一组命中一条即可，不必把组内所有匹配行都列出来
		}
	}
}

type groupRef struct {
	effect string
	text   string
}

// groupRefs 统计每个 IP 组被黑/白名单引用的情况
func (r *WafIPLookupService) groupRefs() map[string]groupRef {
	refs := map[string]groupRef{}

	var blockRows []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("ip_type = ?", model.IPEntryTypeGroup).Find(&blockRows)
	for _, row := range blockRows {
		if row.GroupCode == "" {
			continue
		}
		refs[row.GroupCode] = groupRef{effect: "block", text: "被IP黑名单引用，命中即拦截"}
	}

	var allowRows []model.IPAllowList
	global.GWAF_LOCAL_DB.Where("ip_type = ?", model.IPEntryTypeGroup).Find(&allowRows)
	for _, row := range allowRows {
		if row.GroupCode == "" {
			continue
		}
		if old, ok := refs[row.GroupCode]; ok && old.effect == "block" {
			// 同一个组既被黑名单又被白名单引用：白名单先判，实际效果是放行
			refs[row.GroupCode] = groupRef{effect: "allow", text: "同时被黑白名单引用，白名单优先，实际放行"}
			continue
		}
		refs[row.GroupCode] = groupRef{effect: "allow", text: "被IP白名单引用，命中即放行"}
	}
	return refs
}

// matchThreatIP 威胁情报动辄十万条，逐渠道解压比对很贵。
// 先用引擎那份全局并集(ipset 常数级判定)问一句「在不在」，不在就直接收工；
// 只有确实命中了才展开各渠道快照去定位是哪一家收录的。
func (r *WafIPLookupService) matchThreatIP(ip string, parsed net.IP, resp *response2.IPLookupResp) {
	// 排除名单必须参与进来：查询结果要回答的是"这个 IP 现在会不会被拦"，
	// 用户排除完再来查却还显示 block，只会让他以为排除没生效。
	exclude := WafThreatIPExcludeServiceApp.Get()

	// 被豁免的情况要显式报出来，而且必须在"全局并集里没有"这个早退**之前**判——
	// 排除生效后并集里本来就查不到它了，放在早退之后就永远不会执行。
	// 不报的话用户看到的是"什么都没查到"，分不清是"不在情报里"还是"在情报里但已豁免"。
	if hit := exclude.MatchedEntry(parsed); hit != nil {
		resp.Hits = append(resp.Hits, response2.IPLookupHit{
			Source:     srcThreatExclude,
			SourceName: "威胁情报排除名单",
			Scope:      hit.ScopeText(),
			Matched:    hit.Raw,
			Effect:     "allow",
			Detail:     "该地址已被误报排除名单豁免，威胁情报不会拦截它（其它名单仍可能拦截）",
		})
	}

	matcher := ipset.GetGlobalThreatMatcher()
	if matcher == nil || !matcher.Contains(parsed) {
		return
	}

	var channels []model.ThreatIPChannel
	if err := global.GWAF_LOCAL_DB.Where("enable = ?", 1).Find(&channels).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcThreatIP)
		return
	}

	// 缓存 key 必须带上排除集指纹：排除名单变了但快照 sha 没变，
	// 只按快照 sha 失效的话缓存不会重建，查询结果会一直停留在排除之前。
	excludeSha := exclude.Sha()

	found := false
	for _, ch := range channels {
		// 只读表头拿 sha，命中缓存就完全不用解压
		var meta model.ThreatIPSnapshot
		if err := global.GWAF_LOCAL_DB.Select("sha256").Where("channel_code = ?", ch.Code).First(&meta).Error; err != nil {
			continue
		}
		decodeFailed := false
		set := matcherFor(threatMatchers, ch.Code, meta.Sha256+"_"+excludeSha, func() []string {
			var snap model.ThreatIPSnapshot
			if err := global.GWAF_LOCAL_DB.Where("channel_code = ?", ch.Code).First(&snap).Error; err != nil {
				return nil
			}
			ips, derr := threatip.DecodeSnapshot(snap.Payload)
			if derr != nil {
				decodeFailed = true
				return nil
			}
			return exclude.Filter(ips).Effective
		})
		if decodeFailed {
			resp.Degraded = append(resp.Degraded, srcThreatIP)
			continue
		}
		if set == nil || !set.Contains(parsed) {
			continue
		}

		// 到这儿才解压一次去定位具体命中的那条规则——命中很罕见，这份开销可以接受。
		// entry 就是"实际命中的那条原文"，可能是个网段(如 1.2.3.0/24)；
		// 前端的「排除此项」按钮直接拿它预填，用户不必自己判断该排单 IP 还是整段。
		entry := ""
		var snap model.ThreatIPSnapshot
		if err := global.GWAF_LOCAL_DB.Where("channel_code = ?", ch.Code).First(&snap).Error; err == nil {
			if ips, derr := threatip.DecodeSnapshot(snap.Payload); derr == nil {
				entry = matchedEntryIn(exclude.Filter(ips).Effective, parsed)
			}
		}
		found = true
		resp.Hits = append(resp.Hits, response2.IPLookupHit{
			Source:      srcThreatIP,
			SourceName:  "威胁情报IP",
			Scope:       ch.Name,
			Matched:     entry,
			Effect:      "block",
			Detail:      "落地层：" + landTargetText(ch.LandTarget),
			SystemLayer: landsOnSystem(ch.LandTarget),
		})
	}

	// 并集说命中、逐渠道却找不到出处：多半是快照与已落地集合不同步(渠道刚停用/刚删)。
	// 这种情况必须如实告诉用户「确实会被拦」，不能因为定位不到渠道就当没命中。
	if !found {
		resp.Hits = append(resp.Hits, response2.IPLookupHit{
			Source:      srcThreatIP,
			SourceName:  "威胁情报IP",
			Scope:       "已落地集合",
			Effect:      "block",
			Detail:      "在生效中的威胁情报集合内，但未能定位到具体渠道(快照可能正在同步)",
			SystemLayer: true,
		})
	}
}

// landsOnSystem 落地层是否含系统防火墙(system/both)。
// 含系统层意味着内核就把包丢了，WAF 白名单救不回来。
func landsOnSystem(v string) bool {
	return v == "system" || v == "both"
}

func landTargetText(v string) string {
	switch v {
	case "waf":
		return "WAF应用层"
	case "system":
		return "系统防火墙"
	case "both":
		return "两者"
	}
	return v
}

// matchIPFailure IP 失败封禁是缓存态的临时封禁，键就是完整 IP，直接查
func (r *WafIPLookupService) matchIPFailure(ip string, resp *response2.IPLookupResp) {
	if global.GCACHE_WAFCACHE == nil {
		resp.Degraded = append(resp.Degraded, srcIPFailure)
		return
	}
	key := enums.CACHE_IP_FAILURE_PRE + ip
	if !global.GCACHE_WAFCACHE.IsKeyExist(key) {
		return
	}

	detail := "自动封禁中"
	if manager := wafipban.GetIPFailureManager(); manager != nil {
		if record := manager.GetFailureInfo(ip); record != nil && record.TriggerCount > 0 {
			detail = fmt.Sprintf("%d分钟内失败%d次触发封禁", record.TriggerMinutes, record.TriggerCount)
		}
	}
	if remain := r.remainText(enums.CACHE_IP_FAILURE_PRE, ip); remain != "" {
		detail += "，剩余" + remain
	}

	resp.Hits = append(resp.Hits, response2.IPLookupHit{
		Source:     srcIPFailure,
		SourceName: "IP失败封禁",
		Scope:      "全局",
		Effect:     "block",
		Detail:     detail,
	})
}

func (r *WafIPLookupService) matchCCBan(ip string, resp *response2.IPLookupResp) {
	if global.GCACHE_WAFCACHE == nil {
		resp.Degraded = append(resp.Degraded, srcCCBan)
		return
	}
	if !global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CCVISITBAN_PRE + ip) {
		return
	}
	detail := "CC防护触发的临时封禁"
	if remain := r.remainText(enums.CACHE_CCVISITBAN_PRE, ip); remain != "" {
		detail += "，剩余" + remain
	}
	resp.Hits = append(resp.Hits, response2.IPLookupHit{
		Source:     srcCCBan,
		SourceName: "CC封禁",
		Scope:      "全局",
		Effect:     "block",
		Detail:     detail,
	})
}

// remainText 取缓存剩余时间。缓存接口只给了「按前缀列出可用键」，没有单键 TTL，
// 所以这里列一次再挑出目标键。
func (r *WafIPLookupService) remainText(prefix, ip string) string {
	list := global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(prefix)
	d, ok := list[prefix+ip]
	if !ok || d <= 0 {
		return ""
	}
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	total := int(d.Minutes())
	if total < 60 {
		return fmt.Sprintf("%d分钟", total)
	}
	return fmt.Sprintf("%d小时%d分钟", total/60, total%60)
}

func (r *WafIPLookupService) matchFirewall(ip string, resp *response2.IPLookupResp) {
	var rows []model.FirewallIPBlock
	if err := global.GWAF_LOCAL_DB.Where("status = ?", "active").Find(&rows).Error; err != nil {
		resp.Degraded = append(resp.Degraded, srcFirewall)
		return
	}
	now := time.Now().Unix()
	for _, row := range rows {
		if row.IP == "" || !utils.MatchIPPattern(ip, row.IP) {
			continue
		}
		// 到期未清理的记录还留在表里，但实际已经不封了，不能report成生效中
		if row.ExpireTime > 0 && row.ExpireTime < now {
			continue
		}
		detail := row.Reason
		if row.ExpireTime > 0 {
			detail = strings.TrimSpace(detail + " 到期时间：" + time.Unix(row.ExpireTime, 0).Format("2006-01-02 15:04:05"))
		}
		resp.Hits = append(resp.Hits, response2.IPLookupHit{
			Source:      srcFirewall,
			SourceName:  "防火墙IP封禁",
			Scope:       blockTypeText(row.BlockType),
			Matched:     row.IP,
			Effect:      "block",
			Detail:      detail,
			SystemLayer: true,
		})
	}
}

func blockTypeText(v string) string {
	switch v {
	case "manual":
		return "手动封禁"
	case "auto":
		return "自动封禁"
	case "temp":
		return "临时封禁"
	}
	return v
}

// matchCDN CDN 回源段既不拦也不放，但命中了说明这个 IP 是 CDN 节点、
// 不是真实访客——排查「为什么日志里全是同几个 IP」时这条最关键
func (r *WafIPLookupService) matchCDN(ip string, resp *response2.IPLookupResp) {
	parsed := net.ParseIP(ip)
	views := WafCDNIPServiceApp.GetProviderList()
	for _, v := range views {
		if v.Count <= 0 {
			continue
		}
		// 用快照 sha 当缓存键，厂商段没更新就直接复用编译结果
		var row model.CDNProvider
		sha := ""
		if err := global.GWAF_LOCAL_DB.Select("sha256").Where("provider = ?", v.Provider).First(&row).Error; err == nil {
			sha = row.Sha256
		}
		fetchFailed := false
		set := matcherFor(cdnMatchers, v.Provider, sha, func() []string {
			cidrs, err := WafCDNIPServiceApp.GetProviderCIDRs(v.Provider)
			if err != nil {
				fetchFailed = true
				return nil
			}
			return cidrs
		})
		if fetchFailed {
			resp.Degraded = append(resp.Degraded, srcCDN)
			continue
		}
		if set == nil || !set.Contains(parsed) {
			continue
		}
		entry := ""
		if cidrs, err := WafCDNIPServiceApp.GetProviderCIDRs(v.Provider); err == nil {
			entry = matchedEntryIn(cidrs, parsed)
		}
		resp.Hits = append(resp.Hits, response2.IPLookupHit{
			Source:     srcCDN,
			SourceName: "CDN回源IP",
			Scope:      v.Name,
			Matched:    entry,
			Effect:     "none",
			Detail:     "该IP属于CDN回源节点，不是真实访客IP",
		})
	}
}
