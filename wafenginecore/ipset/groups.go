package ipset

import (
	"strings"
	"sync"
	"sync/atomic"
)

// groups.go 承载「IP 组」的编译成品快照。
//
// 为什么放在 ipset 这个叶子包：判定侧(wafenginecore)与写入侧(service/waf_service)
// 都要访问它，放任何一边都会形成 import cycle。这与威胁情报(global.go)的处理一致。
//
// 为什么用全局快照而不是把组内容展开进每个站点的 HostSafe：
// IP 组的核心诉求是「改一次，所有绑定站点(含全局网站)立即同步」。若展开进各站点，
// 改一次组就要对每个引用站点做一次 UpdateHost，而 UpdateHost 会 clone 整张路由表——
// 1000 个站点引用同一个组时就是 1000 次全表 clone。改成全局快照后，
// 无论多少站点引用，改组只做 1 次原子指针替换，所有站点在同一瞬间同时生效，
// 零通道消息、零竞态、无中间不一致状态。
//
// HostSafe 里只保存「本站引用了哪些组的 code」（字符串切片），判定时用 code 查本快照。

// GroupSnapshot 是「所有 IP 组编译成品」的不可变快照。
// 一经发布即只读，请求热路径无锁读；任何变更都走 COW（复制 map → 改 → 原子替换）。
//
// ByName 与 ByCode 共享同一批 *MatchSet 指针，只是多一份索引，
// 目的是让自定义规则里能写 RF.IPInGroup(MF.SRC_IP,"办公室出口") 而不是写一串 uuid。
type GroupSnapshot struct {
	ByCode map[string]*MatchSet
	ByName map[string]*MatchSet
}

var (
	groupSnapshot atomic.Pointer[GroupSnapshot]

	// groupsMu 保护「读旧快照 → 复制修改 → Store」这个 read-modify-write 序列。
	// 只有写者需要它，读者永远无锁。
	// 缺了它，两个并发的单组更新会各自基于旧快照复制，后写者覆盖先写者 → 丢更新。
	groupsMu sync.Mutex
)

// SetGroupSnapshot 整体发布一份新快照（启动首次构建、删除组、异常兜底时使用）。
// 传 nil 表示清空所有组。
func SetGroupSnapshot(s *GroupSnapshot) {
	groupsMu.Lock()
	defer groupsMu.Unlock()
	groupSnapshot.Store(s)
}

// UpsertGroupMatcher 新增或替换单个组的匹配集（COW）。
// 组内 IP 增删改、组改名后调用，只影响这一个组，其它组的指针原样保留。
//
// name 为空时只登记 code 索引。改名场景下同一个 code 的旧 name 会被清理，
// 避免旧名字继续可用。
func UpsertGroupMatcher(code, name string, m *MatchSet) {
	if code == "" {
		return
	}
	groupsMu.Lock()
	defer groupsMu.Unlock()

	next := cloneSnapshotLocked()
	// 先摘掉该 code 之前占用的 name 索引（处理改名）
	if old, ok := next.ByCode[code]; ok {
		for n, mm := range next.ByName {
			if mm == old {
				delete(next.ByName, n)
			}
		}
	}
	next.ByCode[code] = m
	if name != "" {
		next.ByName[name] = m
	}
	groupSnapshot.Store(next)
}

// RemoveGroupMatcher 从快照中摘除一个组（COW）。
//
// 调用时机很重要：删除 IP 组时必须先删库里的引用行、再摘快照。
// 顺序反了会出现「引用行还在、匹配集已空」的窗口——对白名单来说就是短暂失效，
// 会误拦合法用户。反过来的中间态只是「按删除前的配置多生效几十毫秒」，是安全方向。
func RemoveGroupMatcher(code string) {
	if code == "" {
		return
	}
	groupsMu.Lock()
	defer groupsMu.Unlock()

	cur := groupSnapshot.Load()
	if cur == nil {
		return
	}
	old, ok := cur.ByCode[code]
	if !ok {
		return
	}
	next := cloneSnapshotLocked()
	delete(next.ByCode, code)
	for n, mm := range next.ByName {
		if mm == old {
			delete(next.ByName, n)
		}
	}
	groupSnapshot.Store(next)
}

// cloneSnapshotLocked 复制当前快照。调用方必须已持有 groupsMu。
func cloneSnapshotLocked() *GroupSnapshot {
	cur := groupSnapshot.Load()
	next := &GroupSnapshot{
		ByCode: make(map[string]*MatchSet),
		ByName: make(map[string]*MatchSet),
	}
	if cur != nil {
		for k, v := range cur.ByCode {
			next.ByCode[k] = v
		}
		for k, v := range cur.ByName {
			next.ByName[k] = v
		}
	}
	return next
}

// GetGroupMatcher 按组短码取匹配集。两层 nil 安全（快照未发布 / 组不存在），
// 返回的 nil *MatchSet 调用 Contains 同样安全返回 false，调用方无需判空。
func GetGroupMatcher(code string) *MatchSet {
	s := groupSnapshot.Load()
	if s == nil {
		return nil
	}
	return s.ByCode[code]
}

// LookupGroupMatcher 按「组短码或组名称」取匹配集，短码优先。
// 供自定义规则使用（用户在规则里写组名比写 uuid 直观得多）。
func LookupGroupMatcher(codeOrName string) *MatchSet {
	s := groupSnapshot.Load()
	if s == nil {
		return nil
	}
	key := strings.TrimSpace(codeOrName)
	if m, ok := s.ByCode[key]; ok {
		return m
	}
	return s.ByName[key]
}

// GroupStats 返回当前快照里的组数与条目总数，供日志与管理端展示。
func GroupStats() (groups int, entries int) {
	s := groupSnapshot.Load()
	if s == nil {
		return 0, 0
	}
	for _, m := range s.ByCode {
		groups++
		entries += m.Len()
	}
	return groups, entries
}
