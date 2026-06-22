package wafenginecore

import (
	"SamWaf/model/wafenginmodel"
)

// routingTable 不可变路由快照（RCU）。
//
// 发布(Store)之后只读、永不就地修改；写者一律 copy-on-write：复制出新表 → 在副本上改 → 原子替换。
// 这样请求热路径读它时无需任何锁，也不会读到撕裂/半改状态。
//
// 4 张表的含义与原 WafEngine 字段一致：
//   - HostTarget:           host:port -> *HostSafe
//   - HostCode:             主机code -> host:port(主端口)
//   - HostTargetNoPort:     域名 -> host:port(宽松端口模式)
//   - HostTargetMoreDomain: 域名:port -> 主机code(一机绑多域名)
//
// 注意：HostSafe.LoadBalanceRuntime 是“共享可变”子对象（每请求轮询状态 + 自带 Mux），
// COW 浅拷贝 HostSafe 时共享其指针、绝不深拷贝。
type routingTable struct {
	HostTarget           map[string]*wafenginmodel.HostSafe
	HostCode             map[string]string
	HostTargetNoPort     map[string]string
	HostTargetMoreDomain map[string]string
}

// newRoutingTable 返回一张空表。
func newRoutingTable() *routingTable {
	return &routingTable{
		HostTarget:           map[string]*wafenginmodel.HostSafe{},
		HostCode:             map[string]string{},
		HostTargetNoPort:     map[string]string{},
		HostTargetMoreDomain: map[string]string{},
	}
}

// emptyRoutingTable 兜底空表（routing 尚未发布时返回，避免 nil 解引用，主要用于未初始化的单测）。
var emptyRoutingTable = newRoutingTable()

// rt 返回当前已发布的路由快照（热路径读，无锁）。永不为 nil。
func (waf *WafEngine) rt() *routingTable {
	if t := waf.routing.Load(); t != nil {
		return t
	}
	return emptyRoutingTable
}

// InitRouting 初始化/重置为一张空表（引擎构建时调用；CloseWaf 也复用）。
func (waf *WafEngine) InitRouting() {
	waf.routing.Store(newRoutingTable())
}

// clone 浅拷贝路由表：新建 4 个 map 头、复用其中的 HostSafe 指针与字符串值。
// 供写者在副本上增删改后 Store，发布前对读者不可见。
func (t *routingTable) clone() *routingTable {
	nt := &routingTable{
		HostTarget:           make(map[string]*wafenginmodel.HostSafe, len(t.HostTarget)),
		HostCode:             make(map[string]string, len(t.HostCode)),
		HostTargetNoPort:     make(map[string]string, len(t.HostTargetNoPort)),
		HostTargetMoreDomain: make(map[string]string, len(t.HostTargetMoreDomain)),
	}
	for k, v := range t.HostTarget {
		nt.HostTarget[k] = v
	}
	for k, v := range t.HostCode {
		nt.HostCode[k] = v
	}
	for k, v := range t.HostTargetNoPort {
		nt.HostTargetNoPort[k] = v
	}
	for k, v := range t.HostTargetMoreDomain {
		nt.HostTargetMoreDomain[k] = v
	}
	return nt
}

// withWriteTable 在 writeMu 保护下，克隆当前表 → 交给 fn 修改 → 原子发布。
// 所有“结构级”写者（增删 host/端口、全量重建）都应走它，确保读者只看到完整快照。
func (waf *WafEngine) withWriteTable(fn func(nt *routingTable)) {
	waf.writeMu.Lock()
	defer waf.writeMu.Unlock()
	nt := waf.rt().clone()
	fn(nt)
	waf.routing.Store(nt)
}

// UpdateHost 字段级热更新（copy-on-write）：按 code 定位 HostSafe，浅拷贝副本，
// 在副本上执行 mutator，再把新表中所有指向旧 HostSafe 的 key 一并改指向新副本，原子发布。
//
// 用于运行期改某站点的规则/IP名单/拦截页/AntiCC 等。绝不就地改已发布的 HostSafe。
// LoadBalanceRuntime 指针随浅拷贝共享（其内部由自己的 Mux 保护），不在此处替换。
//
// 重要：mutator 内若要改“指针型且会被读端并发访问”的字段（如 Rule *RuleHelper），
// 必须构造新对象后整体替换 h.Rule，不能就地改旧对象（旧对象仍被其他快照引用）。
func (waf *WafEngine) UpdateHost(hostCode string, mutator func(h *wafenginmodel.HostSafe)) {
	waf.writeMu.Lock()
	defer waf.writeMu.Unlock()
	cur := waf.rt()
	key, ok := cur.HostCode[hostCode]
	if !ok || key == "" {
		return
	}
	waf.applyHostUpdateLocked(cur, key, mutator)
}

// UpdateHostByKey 同 UpdateHost，但按 host:port key 定位（用于只有 key 没有 code 的场景，如 GUARD_STATUS 热更）。
func (waf *WafEngine) UpdateHostByKey(hostKey string, mutator func(h *wafenginmodel.HostSafe)) {
	waf.writeMu.Lock()
	defer waf.writeMu.Unlock()
	waf.applyHostUpdateLocked(waf.rt(), hostKey, mutator)
}

// applyHostUpdateLocked 字段级 COW 的核心，必须在 writeMu 下调用：
// 浅拷贝目标 HostSafe→跑 mutator→新表中所有指向旧 HostSafe 的 key 改指向新副本→原子发布。
func (waf *WafEngine) applyHostUpdateLocked(cur *routingTable, hostKey string, mutator func(h *wafenginmodel.HostSafe)) {
	old, ok := cur.HostTarget[hostKey]
	if !ok || old == nil {
		return
	}
	cp := *old // 浅拷贝（含 LoadBalanceRuntime 指针共享）
	mutator(&cp)

	nt := cur.clone()
	for k, v := range nt.HostTarget {
		if v == old {
			nt.HostTarget[k] = &cp
		}
	}
	waf.routing.Store(nt)
}

// GetHostByCode 按主机 code 从当前快照取 HostSafe（无锁读）。供管理端通道处理等外部包使用。
func (waf *WafEngine) GetHostByCode(hostCode string) (*wafenginmodel.HostSafe, bool) {
	cur := waf.rt()
	key, ok := cur.HostCode[hostCode]
	if !ok || key == "" {
		return nil, false
	}
	h, ok := cur.HostTarget[key]
	return h, ok && h != nil
}

// ResetHostProxiesByKey 清空指定 host:port 的已建反向代理，使下次请求按新后端懒重建(见 proxy.go)。
// LoadBalanceRuntime 是共享可变子对象，在其自身 Mux 下重置，线程安全。
func (waf *WafEngine) ResetHostProxiesByKey(hostKey string) {
	h, ok := waf.rt().HostTarget[hostKey]
	if !ok || h == nil || h.LoadBalanceRuntime == nil {
		return
	}
	h.LoadBalanceRuntime.Mux.Lock()
	h.LoadBalanceRuntime.RevProxies = nil
	h.LoadBalanceRuntime.Mux.Unlock()
}
