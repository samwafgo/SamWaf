// Package ccstats 记录 CC 规则的触发情况，供「命中看板」查看。
//
// 两个刻意的取舍：
//
//	一、只统计「触发」（超过阈值并执行了动作），不统计「匹配」。
//	    匹配是每个请求都会发生的事，在热路径上为它加锁计数等于给正常流量上税；
//	    而真正要回答的问题是「这条规则到底拦到人没有、拦的是谁」。
//	二、只进程内、不落库。落库要么每次触发写一行（把数据库放进热路径），
//	    要么定时聚合（又多一张会长大的表）。这是运维观察窗口，不是审计账本——
//	    需要留痕的信息已经在攻击日志里了。重启归零是预期行为，界面上要写明。
package ccstats

import (
	"sort"
	"sync"
	"time"
)

const (
	// maxRules 同时跟踪的规则数上限。超出后新规则不再收录，已收录的继续统计。
	maxRules = 500
	// maxClientsPerRule 每条规则跟踪的客户端数上限。
	//
	// 满了之后不再收录新客户端，而不是淘汰旧的：看板要回答的是「谁打得最狠」，
	// 而打得狠的那批会持续触发、早早就进了表；为了收录一个新面孔去淘汰一个
	// 已知的重度来源，反而把最该看见的数据挤掉了。截断状态会如实返回给界面。
	maxClientsPerRule = 200
	// TopDefault 看板默认返回的客户端条数
	TopDefault = 50
)

// ClientStat 一个统计维度取值（通常是 IP）的触发情况。
type ClientStat struct {
	DimValue string `json:"dim_value"`
	Count    int64  `json:"count"`
	LastAt   int64  `json:"last_at"` // unix 秒
}

// RuleStat 一条规则的触发情况。
type RuleStat struct {
	RuleId    string           `json:"rule_id"`
	Total     int64            `json:"total"`
	ByAction  map[string]int64 `json:"by_action"`
	FirstAt   int64            `json:"first_at"`
	LastAt    int64            `json:"last_at"`
	Clients   []ClientStat     `json:"clients"`
	Truncated bool             `json:"truncated"` // 客户端表已满，未收录全部来源
}

type clientCell struct {
	count  int64
	lastAt int64
}

type ruleCell struct {
	total     int64
	byAction  map[string]int64
	firstAt   int64
	lastAt    int64
	clients   map[string]*clientCell
	truncated bool
}

// Tracker 触发统计。方法均可并发调用。
type Tracker struct {
	mu    sync.RWMutex
	rules map[string]*ruleCell
	nowFn func() time.Time
	// startedAt 统计窗口的起点。看板要说清「这些数字是从什么时候开始攒的」，
	// 否则一个「触发 3 次」既可能是刚重启也可能是三个月才 3 次。
	startedAt int64
}

// Default 全局实例。引擎与接口层共用一份。
var Default = New()

// New 建一个空的统计器。
func New() *Tracker {
	return &Tracker{
		rules:     make(map[string]*ruleCell),
		nowFn:     time.Now,
		startedAt: time.Now().Unix(),
	}
}

// Record 记一次规则触发。dimValue 是这次触发的统计维度取值（按 IP 统计时就是 IP）。
func (t *Tracker) Record(ruleId, action, dimValue string) {
	if ruleId == "" {
		return
	}
	now := t.nowFn().Unix()

	t.mu.Lock()
	defer t.mu.Unlock()

	rc := t.rules[ruleId]
	if rc == nil {
		if len(t.rules) >= maxRules {
			return
		}
		rc = &ruleCell{
			byAction: make(map[string]int64, 4),
			clients:  make(map[string]*clientCell, 8),
			firstAt:  now,
		}
		t.rules[ruleId] = rc
	}
	rc.total++
	rc.lastAt = now
	if action != "" {
		rc.byAction[action]++
	}
	if dimValue == "" {
		return
	}
	if cc := rc.clients[dimValue]; cc != nil {
		cc.count++
		cc.lastAt = now
		return
	}
	if len(rc.clients) >= maxClientsPerRule {
		rc.truncated = true
		return
	}
	rc.clients[dimValue] = &clientCell{count: 1, lastAt: now}
}

// Counts 返回各规则的触发总数，供规则列表批量填充命中数。
func (t *Tracker) Counts() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]int64, len(t.rules))
	for id, rc := range t.rules {
		out[id] = rc.total
	}
	return out
}

// Board 返回一条规则的看板数据，客户端按触发次数降序取前 topN。
// 规则从未触发过时返回一个各项为零的结果，而不是 nil——
// 「查得到但都是 0」和「查不到」对用户是两件事。
func (t *Tracker) Board(ruleId string, topN int) RuleStat {
	if topN <= 0 {
		topN = TopDefault
	}
	out := RuleStat{RuleId: ruleId, ByAction: map[string]int64{}, Clients: []ClientStat{}}

	t.mu.RLock()
	defer t.mu.RUnlock()

	rc := t.rules[ruleId]
	if rc == nil {
		return out
	}
	out.Total = rc.total
	out.FirstAt = rc.firstAt
	out.LastAt = rc.lastAt
	out.Truncated = rc.truncated
	for k, v := range rc.byAction {
		out.ByAction[k] = v
	}
	list := make([]ClientStat, 0, len(rc.clients))
	for dim, cc := range rc.clients {
		list = append(list, ClientStat{DimValue: dim, Count: cc.count, LastAt: cc.lastAt})
	}
	// 次数相同时按最近触发时间降序，让排序结果稳定、且更有参考价值
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		if list[i].LastAt != list[j].LastAt {
			return list[i].LastAt > list[j].LastAt
		}
		return list[i].DimValue < list[j].DimValue
	})
	if len(list) > topN {
		list = list[:topN]
	}
	out.Clients = list
	return out
}

// StartedAt 统计窗口起点（unix 秒）。
func (t *Tracker) StartedAt() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.startedAt
}

// Drop 清掉一条规则的统计。规则被删除或改动后调用，避免看板显示已经不存在的规则的旧数据。
func (t *Tracker) Drop(ruleId string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.rules, ruleId)
}

// Reset 清空全部统计并重置窗口起点。
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = make(map[string]*ruleCell)
	t.startedAt = t.nowFn().Unix()
}

// Stats 计量值，挂进运行诊断：内存有天花板这件事要在运行期看得见。
func (t *Tracker) Stats() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var clients, truncated int64
	for _, rc := range t.rules {
		clients += int64(len(rc.clients))
		if rc.truncated {
			truncated++
		}
	}
	return map[string]int64{
		"rules":            int64(len(t.rules)),
		"clients":          clients,
		"truncated_rules":  truncated,
		"max_rules":        maxRules,
		"max_clients_rule": maxClientsPerRule,
		"started_at":       t.startedAt,
	}
}
