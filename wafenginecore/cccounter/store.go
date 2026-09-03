package cccounter

// Store 是计数后端的抽象。
//
// 抽出接口是为了给「多节点共享阈值」留位置：单机部署下各节点各算各的，
// 集群里同一个客户端打到不同节点时阈值会被摊薄。
//
// 但默认实现必须是进程内的：计数发生在每个请求上，换成走网络的后端意味着
// 每请求一次往返，攻击流量越大排队越长，防护模块自己就成了瓶颈。
// 因此接入远端后端时要如实告知这个代价，并保留退回进程内的开关。
//
// 远端后端还需要原子自增能力——项目现有的缓存抽象只有读写与过期，
// 没有 INCR 语义，接入前要先补上，否则「读-加-写」在并发下会丢计数。
type Store interface {
	// Incr 累加一次并返回窗口内计数。
	Incr(ruleID, dimValue string, windowSec int) Result
	// Cleanup 回收空闲超过 idleSeconds 的计数键，返回回收数量。
	Cleanup(idleSeconds int64) int
	// DropRule 删除某条规则的全部计数键。
	DropRule(ruleID string)
	// Stats 当前计量值，供运行诊断展示。
	Stats() map[string]int64
}

// 进程内实现必须满足接口约定。
var _ Store = (*Counter)(nil)
