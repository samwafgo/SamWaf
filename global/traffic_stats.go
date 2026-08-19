package global

import (
	"sync"
	"time"
)

// 流量计量累加器：与访问日志完全解耦的站点流量归集。
//
// 为什么不复用日志流做统计（issue #930）：
// 静态资源、大文件下载、chunked/流式响应在引擎里根本不产生访问日志，
// 靠日志字段累加出来的「入站/出站流量」必然只统计到少数 HTML 页，
// 表现为「PV 正常涨、流量永远停在 KB 级」。这里改为在引擎侧直接量真实字节。
//
// 设计要点：
//  1. 桶键带 day / hour_time，且**由请求发生时刻决定**，不是落库时刻。
//     否则 23:59:50 的流量会在 00:00:10 落库时被算到第二天——总量对、分布错。
//  2. 分片加锁：累加只在自己那一片的锁内完成（计数器指针不外泄给锁外使用），
//     Drain 换走整张 map 后，旧 map 不可能再被写入，因此不会丢字节。
//  3. 热路径无 DB、无日志、无分配（桶已存在时）。

// TrafficKey 一个流量桶的键：站点 + 天 + 整点
type TrafficKey struct {
	HostCode string // 网站唯一码
	Host     string // 域名（落库时写入，便于旧行缺失时新建）
	Day      int    // 年月日，如 20260818
	HourTime int64  // 整点 unix 时间戳（秒）
}

// TrafficSnapshot Drain 出来的一个桶的增量
type TrafficSnapshot struct {
	TrafficKey
	In  int64 // 入站字节
	Out int64 // 出站字节
}

const trafficShardCount = 32

type trafficCounter struct {
	in  int64
	out int64
}

type trafficShard struct {
	mu sync.Mutex
	m  map[TrafficKey]*trafficCounter
}

var trafficShards [trafficShardCount]trafficShard

// trafficShardOf 按 host_code 取分片，保证同一站点始终落同一片（减少跨片抖动）
func trafficShardOf(hostCode string) *trafficShard {
	// FNV-1a，避免引入额外依赖
	var h uint32 = 2166136261
	for i := 0; i < len(hostCode); i++ {
		h ^= uint32(hostCode[i])
		h *= 16777619
	}
	return &trafficShards[h&(trafficShardCount-1)]
}

// TrafficBucketOf 由「请求发生时刻」算出天/整点，与 weblog.Day、UNIX_ADD_TIME 同源
func TrafficBucketOf(t time.Time) (day int, hourTime int64) {
	y, m, d := t.Date()
	return y*10000 + int(m)*100 + d, (t.Unix() / 3600) * 3600
}

// AddTraffic 累加一次请求的进出字节。hostCode 为空（未匹配到站点）直接丢弃，无处归属。
func AddTraffic(hostCode, host string, day int, hourTime int64, in, out int64) {
	if hostCode == "" || (in <= 0 && out <= 0) {
		return
	}
	if in < 0 {
		in = 0
	}
	if out < 0 {
		out = 0
	}
	k := TrafficKey{HostCode: hostCode, Host: host, Day: day, HourTime: hourTime}
	s := trafficShardOf(hostCode)
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[TrafficKey]*trafficCounter, 8)
	}
	c := s.m[k]
	if c == nil {
		c = &trafficCounter{}
		s.m[k] = c
	}
	c.in += in
	c.out += out
	s.mu.Unlock()
}

// DrainTraffic 取走全部累计增量并清空。落库侧按增量 UPSERT，所以整体取走是安全的。
func DrainTraffic() []TrafficSnapshot {
	var out []TrafficSnapshot
	for i := range trafficShards {
		s := &trafficShards[i]
		s.mu.Lock()
		old := s.m
		if len(old) == 0 {
			s.mu.Unlock()
			continue
		}
		s.m = make(map[TrafficKey]*trafficCounter, len(old))
		s.mu.Unlock()

		for k, c := range old {
			out = append(out, TrafficSnapshot{TrafficKey: k, In: c.in, Out: c.out})
		}
	}
	return out
}

// RestoreTraffic 落库失败时把增量放回累加器，等下个周期重试，避免直接丢数。
func RestoreTraffic(list []TrafficSnapshot) {
	for _, s := range list {
		AddTraffic(s.HostCode, s.Host, s.Day, s.HourTime, s.In, s.Out)
	}
}

// PendingTrafficBuckets 当前待落库的桶数量（诊断/测试用）
func PendingTrafficBuckets() int {
	n := 0
	for i := range trafficShards {
		s := &trafficShards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}
