package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafenginecore/ipset"
	"SamWaf/wafhostguard"
	"SamWaf/waftask/threatip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 威胁情报误报排除名单。
//
// 设计要点见 SamWafTechDoc/威胁IP库同步/SamWaf-威胁情报IP误报排除-设计文档.md。
// 一句话概括：订阅源是全量快照、每周期整份覆盖，用户手工删掉的条目下次同步就回来；
// 系统层又是内核丢包、WAF 白名单救不了。所以误报必须有一份每次落地都重新应用的本地声明。
//
// 本文件只负责"排除集怎么来、怎么算有效集"，落地判据的改造在 waf_threat_ip_service.go。

type WafThreatIPExcludeService struct {
	mu  sync.Mutex                 // 保护重建过程，避免并发重复编译
	cur atomic.Pointer[ExcludeSet] // 当前排除集(RCU 发布，构建完即只读，读侧无锁)
}

var WafThreatIPExcludeServiceApp = new(WafThreatIPExcludeService)

func (r *WafThreatIPExcludeService) load() *ExcludeSet   { return r.cur.Load() }
func (r *WafThreatIPExcludeService) store(s *ExcludeSet) { r.cur.Store(s) }

// excludeEntry 一条编译好的排除条目
type excludeEntry struct {
	Id       string        // 手工/固化条目的主键；纯配置来源为空
	Raw      string        // 原文
	Reason   string        // 自动来源的原因；手工为空
	Volatile bool          // 易变源(活跃管理会话IP)，命中后需固化
	pat      ipset.Pattern // 解析结果
	exact    bool          // 能否做"网段包含"精确判定(Prefix>=0)
}

// ExcludeSet 编译后的排除集，构建完成即只读。
type ExcludeSet struct {
	entries []excludeEntry
	// fast 是整表编译成的匹配集，只用于**快速否定**：
	// 十万条快照逐条去比对几十个排除条目太贵，先用一次 trie 查询把绝大多数条目挡掉，
	// 只有可能命中的少数条目才进入精确的"网段包含"判定。
	fast *ipset.MatchSet
	// sha 只覆盖**稳定来源**(库里的条目 + 配置类自动源)。
	// 活跃管理会话 IP 有 30 分钟 TTL，算进 sha 会导致 effSha 随 TTL 反复抖动、
	// 每小时对账都判定不一致而重建，所以它靠"命中即固化"转成库里的稳定条目。
	sha string
}

// Sha 排除集的稳定指纹
func (e *ExcludeSet) Sha() string {
	if e == nil {
		return ""
	}
	return e.sha
}

// Len 生效条目数
func (e *ExcludeSet) Len() int {
	if e == nil {
		return 0
	}
	return len(e.entries)
}

// IsEmpty 排除集是否为空。为空时 effectiveIPs 是恒等变换，effSha == contentSha，
// 存量 landed_sha 保持有效，升级不会触发任何重建。
func (e *ExcludeSet) IsEmpty() bool {
	return e == nil || len(e.entries) == 0
}

// Get 取当前排除集，未构建过则构建
func (r *WafThreatIPExcludeService) Get() *ExcludeSet {
	if s := r.load(); s != nil {
		return s
	}
	return r.Rebuild()
}

// Invalidate 丢弃当前排除集，下次取用时重建
func (r *WafThreatIPExcludeService) Invalidate() {
	r.store(nil)
}

// NotifySourceChanged 排除集的**外部来源**发生了变化(内置自动排除依赖的那几项配置：
// 内网段豁免开关、防爆破白名单等)。
//
// 与直接改排除名单同样处理：重建排除集、重建 WAF 并集立即生效、后台跑一次落地对账
// 把系统防火墙拉到一致。effSha 没变时直接返回，不惊动落地——这一步很重要，
// 否则每次改配置都要让整轮对账去枚举一遍系统防火墙规则。
func (r *WafThreatIPExcludeService) NotifySourceChanged() {
	before := r.Get().Sha()
	if r.Rebuild().Sha() == before {
		return // 白名单改的是与威胁情报无关的部分，不必惊动落地
	}
	safeGo("威胁情报排除来源变更后重新落地", func() {
		WafThreatIPServiceApp.RebuildWAFUnion()
		WafThreatIPServiceApp.ReconcileLanding()
	})
}

// Rebuild 由两个来源重建排除集：
//
//	① 内置自动排除(wafhostguard.AutoExcludeSources：回环/本机/内网/配置/管理端/活跃管理会话)
//	② 专用排除名单表 threat_ip_exclude
//
// **刻意不含任何站点的 IP 白名单，包括全局站点。** 起初设计里是含全局站点白名单的，
// 理由是"我明明把办公室 IP 加了全局白名单，结果还是连不上 SSH"很反直觉。实际数据打脸：
// 线上有用户的全局白名单是批量导入的 15 万条，与威胁情报重叠 8000+ 条——
// 等于**在用户完全不知情的情况下把威胁情报静默削掉 25%**，而且每次重建都要
// 从库里捞 15 万行、编译 15 万条匹配集，把管理端接口拖到超时。
//
// 降低防护这件事必须是显式的。要豁免就在排除名单里明确写一条（IP 归属查询里一键就能加），
// 别让它作为另一个功能的副作用悄悄发生。
//
// 站点级白名单同样不含：系统防火墙是整机级的，用 per-host 白名单驱动整机级排除
// 会出现"A 站点的白名单顺带给 SSH 开门"的语义错配。
func (r *WafThreatIPExcludeService) Rebuild() *ExcludeSet {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 配置加载可能早于数据库就绪。此时返回空集(恒等过滤)而**不缓存**，
	// 下次取用会重新构建——缓存了空集就等于永久关闭排除功能直到重启。
	if global.GWAF_LOCAL_DB == nil {
		return &ExcludeSet{}
	}

	entries := make([]excludeEntry, 0, 64)
	seen := make(map[string]struct{}, 64)
	stable := make([]string, 0, 64) // 参与 sha 的稳定条目原文

	appendEntry := func(raw, id, reason string, volatile bool) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		key := strings.ToLower(raw)
		if _, ok := seen[key]; ok {
			return
		}
		pat, err := ipset.ParsePatternLenient(raw)
		if err != nil {
			zlog.Warn("威胁情报排除条目解析失败，已忽略", "entry", raw, "error", err.Error())
			return
		}
		seen[key] = struct{}{}
		entries = append(entries, excludeEntry{
			Id: id, Raw: raw, Reason: reason, Volatile: volatile,
			pat:   pat,
			exact: pat.Prefix >= 0 && len(pat.Mask) == pat.Width,
		})
		if !volatile {
			stable = append(stable, raw)
		}
	}

	// ③ 专用排除名单(仅启用行)
	var rows []model.ThreatIPExclude
	global.GWAF_LOCAL_DB.Where("enable = ?", 1).Find(&rows)
	for _, row := range rows {
		appendEntry(row.Entry, row.Id, row.Reason, false)
	}

	// ① 内置自动排除
	for _, item := range wafhostguard.AutoExcludeSources() {
		appendEntry(item.Entry, "", item.Reason, item.Volatile)
	}

	set := &ExcludeSet{entries: entries}
	if len(entries) > 0 {
		raws := make([]string, 0, len(entries))
		for _, e := range entries {
			raws = append(raws, e.Raw)
		}
		set.fast = ipset.BuildMatchSet(raws)
	}
	sort.Strings(stable)
	sum := sha256.Sum256([]byte(strings.Join(stable, "\n")))
	set.sha = hex.EncodeToString(sum[:])

	r.store(set)
	return set
}

// EffectiveRule 一条**当前生效**的排除规则，供页面展示。
//
// 存在的理由：内置自动来源(回环/本机网卡/内网段/管理端白名单/活跃管理会话)不落库，
// 只看 threat_ip_exclude 表的话，用户会看到"已排除6条"却在排除名单里找不到任何条目，
// 完全不知道是谁排的。降低防护的规则必须全部可见，哪怕它是系统内置的。
type EffectiveRule struct {
	Entry    string `json:"entry"`
	Source   string `json:"source"`   // manual | auto | builtin(内置，不落库、不可删)
	Reason   string `json:"reason"`   // 内置来源的说明，如"内网段自动豁免"
	Editable bool   `json:"editable"` // 是否可在页面上删除/停用
}

// EffectiveRules 列出当前生效的全部排除规则(含不落库的内置来源)
func (r *WafThreatIPExcludeService) EffectiveRules() []EffectiveRule {
	set := r.Get()
	out := make([]EffectiveRule, 0, set.Len())
	for i := range set.entries {
		e := &set.entries[i]
		if e.Id != "" {
			continue // 落库条目由排除名单列表自己展示，这里只补内置来源
		}
		out = append(out, EffectiveRule{
			Entry:    e.Raw,
			Source:   "builtin",
			Reason:   e.Reason,
			Editable: false,
		})
	}
	return out
}

// FilterResult 一次过滤的结果
type FilterResult struct {
	Effective []string       // 有效集：应当真正写进防火墙 / 并入 WAF 集合的内容
	Excluded  int            // 被剔除的条数
	HitsById  map[string]int // 库内条目 Id -> 剔除条数，供回写 hit_count
	// VolatileHits 命中了易变源(活跃管理会话IP)的条目，需要由调用方固化落库，
	// 否则 TTL 一过 effSha 就变回去，会出现"排除生效→过期→重建→又命中"的反复重建。
	VolatileHits []excludeEntry
}

// Filter 由内容集算出有效集。ips 必须是已排序去重的快照内容。
//
// 判定规则(设计文档 §5.1)：剔除快照条目 S，当且仅当存在排除条目 E 使得 S ⊆ E。
// 方向性很重要——排除 1.2.3.4 剔不掉快照里的 1.2.3.0/24，小的排不掉大的。
func (e *ExcludeSet) Filter(ips []string) FilterResult {
	res := FilterResult{HitsById: map[string]int{}}
	if e.IsEmpty() || len(ips) == 0 {
		res.Effective = ips
		return res
	}
	out := make([]string, 0, len(ips))
	volatileSeen := map[string]struct{}{}
	for _, raw := range ips {
		hit := e.matchEntry(raw)
		if hit == nil {
			out = append(out, raw)
			continue
		}
		res.Excluded++
		if hit.Id != "" {
			res.HitsById[hit.Id]++
		}
		if hit.Volatile {
			if _, ok := volatileSeen[hit.Raw]; !ok {
				volatileSeen[hit.Raw] = struct{}{}
				res.VolatileHits = append(res.VolatileHits, *hit)
			}
		}
	}
	res.Effective = out
	return res
}

// MatchedEntry 找出豁免了 ip 的那条排除条目，没有则返回 nil。供 IP 归属查询回答
// "这个 IP 为什么没被威胁情报拦"。
//
// 只认**落库的**排除条目(Id != "")，不认环境类自动来源(回环/本机网卡/内网段/管理端白名单)。
// 后者虽然确实参与过滤，但它们不是"针对威胁情报的误报判断"——查任意一个内网地址都会
// 命中 10.0.0.0/8，报出来只是噪音，还会让用户以为自己排除过这个地址。
// 落库的条目则相反：它的存在本身就意味着有人(或系统固化)判定过"这在威胁情报里是误报"。
func (e *ExcludeSet) MatchedEntry(ip net.IP) *ExcludeHit {
	if e.IsEmpty() || ip == nil {
		return nil
	}
	if e.fast != nil && !e.fast.Contains(ip) {
		return nil
	}
	for i := range e.entries {
		if e.entries[i].Id == "" {
			continue
		}
		if e.entries[i].pat.Match(ip) {
			return &ExcludeHit{Raw: e.entries[i].Raw, Reason: e.entries[i].Reason, Id: e.entries[i].Id}
		}
	}
	return nil
}

// ExcludeHit 一次排除命中的对外描述
type ExcludeHit struct {
	Id     string
	Raw    string
	Reason string
}

// ScopeText 命中来源的展示文案
func (h *ExcludeHit) ScopeText() string {
	if h.Reason != "" {
		return h.Reason
	}
	return "手工排除"
}

// matchEntry 找出剔除 raw 的那条排除条目，没有则返回 nil
func (e *ExcludeSet) matchEntry(raw string) *excludeEntry {
	// 快路径：绝大多数快照条目是**单个 IP**。这时 ParsePattern 的分支判定与 Pattern
	// 结构分配纯属浪费——十万条乘下来很可观，而这个函数会被列表页每行调一次。
	//
	// 对单个 IP 来说 entryCovers 与 pat.Match(ip) 完全等价：
	//   - E 是连续掩码时，S.Prefix 恒为满长度，前缀比较必然通过，只剩掩码比对；
	//   - E 是区间/非连续通配符时，降级路径本来就是 pat.Match。
	if ip := net.ParseIP(raw); ip != nil {
		if e.fast != nil && !e.fast.Contains(ip) {
			return nil
		}
		for i := range e.entries {
			if e.entries[i].pat.Match(ip) {
				return &e.entries[i]
			}
		}
		return nil
	}

	// 慢路径：网段等需要做"包含"判定的条目
	sp, err := ipset.ParsePatternLenient(raw)
	if err != nil {
		return nil // 快照里出现解析不了的内容：保守起见不剔除
	}
	// 快速否定：先用整表匹配集问一句"这条的网络地址有没有可能被排除"
	if e.fast != nil && !e.fast.Contains(net.IP(sp.Value)) {
		return nil
	}
	for i := range e.entries {
		if entryCovers(&e.entries[i], sp) {
			return &e.entries[i]
		}
	}
	return nil
}

// entryCovers 判断排除条目 E 是否**完全包含**快照条目 S。
//
// 两级判定(设计文档 §5.2)：
//   - E 能表达成连续掩码(单IP/CIDR/可降级通配符)时做精确的网段包含判定，能整段剔除；
//   - E 是任意区间或非连续通配符时降级：只剔除快照里的**单 IP** 条目，网段一律不剔除。
//     宁可漏剔也不能错剔——错剔等于悄悄放行一整段真实威胁。
func entryCovers(e *excludeEntry, s ipset.Pattern) bool {
	if e.pat.Width != s.Width {
		return false // 协议族不同
	}
	if !e.exact {
		// 降级路径：只处理单 IP
		if s.Kind != ipset.KindSingle {
			return false
		}
		return e.pat.Match(net.IP(s.Value))
	}
	if s.Prefix < 0 {
		// S 自己是区间/非连续通配符，没有可比较的前缀长度，退化为逐地址判定太贵，
		// 这类内容在威胁情报快照里不存在(源只给单 IP 和 CIDR)，直接不剔除
		return false
	}
	// E 必须不小于 S，否则是"小的想排掉大的"
	if e.pat.Prefix > s.Prefix {
		return false
	}
	// S 的网络地址套上 E 的掩码后应当等于 E 的网络地址
	masked := make([]byte, e.pat.Width)
	for i := 0; i < e.pat.Width; i++ {
		masked[i] = s.Value[i] & e.pat.Mask[i]
	}
	return bytes.Equal(masked, e.pat.Value)
}

// EffectiveIPs 由快照内容算出有效集与其 sha。
//
// **这是整个误报排除功能的唯一真相源**：同步落地、启动重放、落地对账、WAF 并集、
// 页面条数、归属查询全部必须经由此处，任何一处直接用快照原文都会导致
// "落地的是 N-k 条、对账的期望还是 N 条"，于是每小时全量重建且永远对不上。
func (r *WafThreatIPExcludeService) EffectiveIPs(ips []string) (eff []string, effSha string, excluded int) {
	set := r.Get()
	res := set.Filter(ips)
	r.promoteVolatile(res.VolatileHits)
	return res.Effective, threatip.ShaOf(res.Effective), res.Excluded
}

// promoteVolatile 把命中了易变源的条目固化成库里的排除记录。
//
// 活跃管理会话 IP 只记 30 分钟。如果它真的从威胁情报里剔掉了东西，说明
// "管理员自己的 IP 被情报源当成了恶意 IP"——这正是最该长期排除的情况。
// 不固化的话 TTL 一过 effSha 就变回去，会出现"排除生效→过期→重建→又命中→再变"的
// 反复重建；固化之后只抖一次，而且用户在页面上看得见系统替他做了什么。
func (r *WafThreatIPExcludeService) promoteVolatile(hits []excludeEntry) {
	if len(hits) == 0 {
		return
	}
	changed := false
	for _, h := range hits {
		var cnt int64
		global.GWAF_LOCAL_DB.Model(&model.ThreatIPExclude{}).Where("entry = ?", h.Raw).Count(&cnt)
		if cnt > 0 {
			continue
		}
		row := model.ThreatIPExclude{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			Entry:  h.Raw,
			Source: model.ThreatExcludeSourceAuto,
			Reason: h.Reason,
			Enable: 1,
			Remarks: fmt.Sprintf("系统自动排除：%s。该地址被威胁情报源收录，为避免把自己锁在门外已固化保留，"+
				"确认无误后可手工删除。", h.Reason),
		}
		if err := global.GWAF_LOCAL_DB.Create(&row).Error; err != nil {
			zlog.Error("固化自动排除条目失败: " + err.Error())
			continue
		}
		changed = true
		zlog.Warn("检测到自己人被威胁情报收录，已自动加入排除名单", "entry", h.Raw, "reason", h.Reason)
		WafThreatIPExcludeAuditApp.Write(model.ThreatIPExcludeAudit{
			Action: model.ThreatExcludeActionAdd, Entry: h.Raw,
			Source: model.ThreatExcludeSourceAuto, Reason: h.Reason,
			Operator: "system", Remarks: "自动固化：该地址命中活跃管理会话IP豁免",
		})
	}
	if changed {
		r.Invalidate()
	}
}

// ApplyHitCounts 回写各排除条目"本轮实际剔除了多少条"。
//
// 这个数字是给用户看的：最典型的误用是排除了 1.2.3.4，而快照里其实是 1.2.3.0/24，
// 此时 hit_count 恒为 0，用户一眼就能看出"写了但没生效"。
func (r *WafThreatIPExcludeService) ApplyHitCounts(hits map[string]int) {
	if len(hits) == 0 {
		return
	}
	now := time.Now().Unix()
	for id, n := range hits {
		global.GWAF_LOCAL_DB.Model(&model.ThreatIPExclude{}).Where("id = ?", id).
			Updates(map[string]interface{}{"hit_count": n, "last_hit_at": now, "update_time": customtype.JsonTime(time.Now())})
	}
}

// ---------- 增删改查 ----------

// PreviewResult 试算结果：这条排除会影响哪些渠道、剔掉多少条
type PreviewResult struct {
	Entry         string   `json:"entry"`
	AffectedChans int      `json:"affected_chans"`
	AffectedItems int      `json:"affected_items"`
	ChannelNames  []string `json:"channel_names"`
	// SampleMatched 命中的快照条目样例(最多 5 条)。
	// 用户排除 1.2.3.4 却没生效时，这里会显示 1.2.3.0/24，直接告诉他该排整段。
	SampleMatched []string `json:"sample_matched"`
	// CoveringEntry 若 entry 本身没剔掉任何东西，但它落在某个更大的快照网段里，
	// 这里给出那个网段，前端据此提示"需排除整段"
	CoveringEntry string `json:"covering_entry"`
}

// Preview 试算一条排除条目的影响，不落库。
func (r *WafThreatIPExcludeService) Preview(entry string) (*PreviewResult, error) {
	entry = strings.TrimSpace(entry)
	if err := ValidateExcludeEntry(entry); err != nil {
		return nil, err
	}
	pat, err := ipset.ParsePatternLenient(entry)
	if err != nil {
		return nil, err
	}
	one := &ExcludeSet{
		entries: []excludeEntry{{
			Raw: entry, pat: pat,
			exact: pat.Prefix >= 0 && len(pat.Mask) == pat.Width,
		}},
		fast: ipset.BuildMatchSet([]string{entry}),
	}

	out := &PreviewResult{Entry: entry, ChannelNames: []string{}, SampleMatched: []string{}}
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = ?", 1).Find(&channels)
	for _, ch := range channels {
		ips, _ := WafThreatIPServiceApp.loadSnapshot(ch.Code)
		if len(ips) == 0 {
			continue
		}
		hit := 0
		for _, ip := range ips {
			if one.matchEntry(ip) != nil {
				hit++
				if len(out.SampleMatched) < 5 {
					out.SampleMatched = append(out.SampleMatched, ip)
				}
			}
		}
		if hit > 0 {
			out.AffectedChans++
			out.AffectedItems += hit
			out.ChannelNames = append(out.ChannelNames, ch.Name)
			continue
		}
		// 没剔掉任何东西：看看它是不是落在某个更大的网段里(方向性陷阱)
		if out.CoveringEntry == "" {
			out.CoveringEntry = coveringEntryIn(ips, pat)
		}
	}
	return out, nil
}

// coveringEntryIn 找出 ips 里**包含** pat 的那条网段(用于"小的排不掉大的"的提示)
func coveringEntryIn(ips []string, pat ipset.Pattern) string {
	for _, raw := range ips {
		sp, err := ipset.ParsePatternLenient(raw)
		if err != nil || sp.Width != pat.Width || sp.Prefix < 0 || sp.Prefix >= pat.Prefix {
			continue
		}
		e := excludeEntry{Raw: raw, pat: sp, exact: len(sp.Mask) == sp.Width}
		if entryCovers(&e, pat) {
			return raw
		}
	}
	return ""
}

// ValidateExcludeEntry 校验一条排除条目。写入路径专用，严格。
func ValidateExcludeEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return fmt.Errorf("排除条目不能为空")
	}
	if len(entry) > 64 {
		return fmt.Errorf("排除条目长度不能超过64个字符")
	}
	pat, err := ipset.ParsePattern(entry)
	if err != nil {
		return fmt.Errorf("格式不合法：%s（仅支持单个IP或CIDR网段，如 1.2.3.4 或 1.2.3.0/24）", err.Error())
	}
	if pat.Kind != ipset.KindSingle && pat.Kind != ipset.KindCIDR {
		return fmt.Errorf("排除条目仅支持单个IP或CIDR网段，不支持通配符与区间写法")
	}
	// 排除一个巨型网段等于把整个威胁情报功能悄悄关掉，必须在写入侧挡死
	if pat.Width == net.IPv4len && pat.Prefix < 8 {
		return fmt.Errorf("IPv4 排除网段不能大于 /8（当前 /%d）：这会让威胁情报形同虚设", pat.Prefix)
	}
	if pat.Width == net.IPv6len && pat.Prefix < 32 {
		return fmt.Errorf("IPv6 排除网段不能大于 /32（当前 /%d）：这会让威胁情报形同虚设", pat.Prefix)
	}
	return nil
}

// AddApi 新增排除条目
func (r *WafThreatIPExcludeService) AddApi(req request.WafThreatIPExcludeAddReq, operator, operatorIP string) (*PreviewResult, error) {
	entry := strings.TrimSpace(req.Entry)
	if err := ValidateExcludeEntry(entry); err != nil {
		return nil, err
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.ThreatIPExclude{}).Where("entry = ?", entry).Count(&cnt)
	if cnt > 0 {
		return nil, fmt.Errorf("该排除条目已存在：%s", entry)
	}
	row := model.ThreatIPExclude{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Entry:   entry,
		Source:  model.ThreatExcludeSourceManual,
		Remarks: req.Remarks,
		Enable:  1,
	}
	if err := global.GWAF_LOCAL_DB.Create(&row).Error; err != nil {
		return nil, err
	}
	res := r.applyChange()
	WafThreatIPExcludeAuditApp.Write(model.ThreatIPExcludeAudit{
		Action: model.ThreatExcludeActionAdd, Entry: entry,
		Source: model.ThreatExcludeSourceManual, Operator: operator, OperatorIP: operatorIP,
		AffectedChans: res.AffectedChans, AffectedItems: res.AffectedItems, Remarks: req.Remarks,
	})
	res.Entry = entry
	return res, nil
}

// DelApi 删除排除条目(删除后该 IP 会重新被封)
func (r *WafThreatIPExcludeService) DelApi(id, operator, operatorIP string) error {
	var row model.ThreatIPExclude
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&row).Error; err != nil {
		return fmt.Errorf("排除条目不存在")
	}
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).Delete(model.ThreatIPExclude{}).Error; err != nil {
		return err
	}
	res := r.applyChange()
	WafThreatIPExcludeAuditApp.Write(model.ThreatIPExcludeAudit{
		Action: model.ThreatExcludeActionDel, Entry: row.Entry,
		Source: row.Source, Reason: row.Reason, Operator: operator, OperatorIP: operatorIP,
		AffectedChans: res.AffectedChans, AffectedItems: res.AffectedItems,
		Remarks: "删除排除条目，该地址将重新按威胁情报拦截",
	})
	return nil
}

// ModifyApi 改备注 / 启停
func (r *WafThreatIPExcludeService) ModifyApi(req request.WafThreatIPExcludeEditReq, operator, operatorIP string) error {
	var row model.ThreatIPExclude
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&row).Error; err != nil {
		return fmt.Errorf("排除条目不存在")
	}
	enableChanged := row.Enable != req.Enable
	if err := global.GWAF_LOCAL_DB.Model(&model.ThreatIPExclude{}).Where("id = ?", req.Id).
		Updates(map[string]interface{}{
			"remarks":     req.Remarks,
			"enable":      req.Enable,
			"update_time": customtype.JsonTime(time.Now()),
		}).Error; err != nil {
		return err
	}
	if !enableChanged {
		return nil
	}
	res := r.applyChange()
	action := model.ThreatExcludeActionEnable
	if req.Enable == 0 {
		action = model.ThreatExcludeActionDisable
	}
	WafThreatIPExcludeAuditApp.Write(model.ThreatIPExcludeAudit{
		Action: action, Entry: row.Entry, Source: row.Source, Reason: row.Reason,
		Operator: operator, OperatorIP: operatorIP,
		AffectedChans: res.AffectedChans, AffectedItems: res.AffectedItems, Remarks: req.Remarks,
	})
	return nil
}

// GetListApi 分页查询排除名单
func (r *WafThreatIPExcludeService) GetListApi(req request.WafThreatIPExcludeSearchReq) ([]model.ThreatIPExclude, int64, error) {
	var list []model.ThreatIPExclude
	var total int64
	db := global.GWAF_LOCAL_DB.Model(&model.ThreatIPExclude{})
	if s := strings.TrimSpace(req.Source); s != "" {
		db = db.Where("source = ?", s)
	}
	if k := strings.TrimSpace(req.Entry); k != "" {
		db = db.Where("entry LIKE ?", "%"+k+"%")
	}
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := db.Order("create_time DESC").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	return list, total, err
}

// applyChange 排除名单变更后的统一生效路径：
//
//	重建排除集 → 重建 WAF 并集(毫秒级立即生效) → 逐渠道对账重建系统防火墙
//
// 系统层复用 ReconcileLanding：它以有效集为期望值，排除变了 effSha 就变，
// 自然会发现落地态对不上并覆盖式重建；effSha 没变的渠道原地跳过，
// 不会为了一个不在任何渠道里的 IP 做几十次 netsh 的无谓重建。
func (r *WafThreatIPExcludeService) applyChange() *PreviewResult {
	r.Rebuild()
	out := &PreviewResult{ChannelNames: []string{}, SampleMatched: []string{}}

	set := r.Get()
	var channels []model.ThreatIPChannel
	global.GWAF_LOCAL_DB.Where("enable = ?", 1).Find(&channels)
	for _, ch := range channels {
		ips, _ := WafThreatIPServiceApp.loadSnapshot(ch.Code)
		if len(ips) == 0 {
			continue
		}
		res := set.Filter(ips)
		if res.Excluded > 0 {
			out.AffectedChans++
			out.AffectedItems += res.Excluded
			out.ChannelNames = append(out.ChannelNames, ch.Name)
		}
	}

	WafThreatIPServiceApp.RebuildWAFUnion()
	safeGo("威胁情报排除变更后落地对账", func() {
		WafThreatIPServiceApp.ReconcileLanding()
	})
	return out
}
