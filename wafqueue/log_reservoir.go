package wafqueue

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

// sampleNegPerSiteDay 每个站点每天最多留多少条正常请求的报文（AI 训练的负样本池，D2）。
// 正常请求报文一律不留会把「空 body」学成正常，模型阈值随之失效；全留又失去了分层的意义。
// 蓄水池采样保证当天流量无论多大，留下来的都是等概率的 500 条。
const sampleNegPerSiteDay = 500

// sampleFlushInterval 蓄水池攒多久往 event_payload 落一次。
// 采样行是「丢了不可惜」的数据，攒批换来的是写入次数与流量解耦。
const sampleFlushInterval = 10 * time.Second

// sampleReservoir 按「站点 × 天」做蓄水池采样（algorithm R：前 N 条全留，
// 之后第 i 条以 N/i 的概率替换池中随机一条，全程等概率、池子上限恒定）。
//
// 为什么不能采中即落库：蓄水池的「替换」意味着后来被采中的会挤掉先来的，
// 即采即写会留下一堆早已被挤出池的行。所以池子留在内存（上限 500 条/站点/天，
// 截断后单条 ≤64KB），隔 sampleFlushInterval 把有变化的池子整池刷进 event_payload
// （主键 DoNothing，已在库里的行自动跳过）；进程退出丢失未刷的部分，样本数据可以接受。
//
// 只有日志队列一个协程在写，锁为单测与将来可能的第二写者兜底。
type sampleReservoir struct {
	mu        sync.Mutex
	buckets   map[string]*sampleBucket
	lastFlush time.Time
}

type sampleBucket struct {
	day   int
	seen  int
	pick  []*model.EventPayload
	dirty bool
}

var negSampler = &sampleReservoir{buckets: map[string]*sampleBucket{}}

// Pick 把一条正常请求交给蓄水池；返回 true 表示它当前在池里（调用方在 sample 档下为它写窄行）。
// 报文全空的请求不采（空报文对 AI 训练没有价值，留着只会挤占配额）。
func (r *sampleReservoir) Pick(lg *innerbean.WebLog) bool {
	p := extractPayload(lg, PayloadKindSample)
	if p == nil {
		return false
	}

	today, _ := strconv.Atoi(time.Now().Format("20060102"))
	day := lg.Day
	if day <= 0 {
		day = today
	}
	key := lg.HOST_CODE + "|" + strconv.Itoa(day)

	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil || b.day != day {
		b = &sampleBucket{day: day, pick: make([]*model.EventPayload, 0, sampleNegPerSiteDay)}
		r.buckets[key] = b
		// 顺路清掉过期 bucket，免得跨天运行的实例慢慢涨
		for k, old := range r.buckets {
			if old.day != day && old.day != today {
				delete(r.buckets, k)
			}
		}
	}
	b.seen++
	i := b.seen
	if i <= sampleNegPerSiteDay {
		b.pick = append(b.pick, p)
		b.dirty = true
		return true
	}
	if j := rand.Intn(i); j < sampleNegPerSiteDay {
		b.pick[j] = p
		b.dirty = true
		return true
	}
	return false
}

// FlushIfDue 到点就把有变化的池子刷进报文表。日志队列每轮都会调，节流在这层。
func (r *sampleReservoir) FlushIfDue() {
	r.mu.Lock()
	if time.Since(r.lastFlush) < sampleFlushInterval {
		r.mu.Unlock()
		return
	}
	r.lastFlush = time.Now()
	var out []*model.EventPayload
	for _, b := range r.buckets {
		if !b.dirty {
			continue
		}
		b.dirty = false
		out = append(out, b.pick...)
	}
	r.mu.Unlock()
	storePayloads(out)
}

// snapshot 当前池内容（单测用）
func (r *sampleReservoir) snapshot() []*model.EventPayload {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*model.EventPayload
	for _, b := range r.buckets {
		out = append(out, b.pick...)
	}
	return out
}
