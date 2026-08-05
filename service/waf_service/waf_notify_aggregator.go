package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
*
订阅级通知聚合器（issue #822）

与老的 wafqueue/notify_aggregator.go 的区别：

	老实现：全局一个缓冲区、固定 10 秒窗口、按 messageType 分组。
	        所有订阅共享同一个节奏，用户改不了，也没法让不同渠道有不同合并策略。
	现实现：按「订阅 × 去重key」分桶，每个桶带自己的 deadline（窗口取该订阅的生效配置）。
	        飞书可以 60 秒合并一次、邮件可以直发，互不干扰。
*/

const (
	aggBucketMaxEntries = 100  // 单桶条数上限，超过立即刷新
	aggMaxBuckets       = 5000 // 桶数量上限，超过强制全刷，防止内存无限增长
	aggTickInterval     = time.Second
)

// aggBucket 一个聚合桶
type aggBucket struct {
	sub       model.NotifySubscription
	channel   model.NotifyChannel
	dedupKey  string
	events    []NotifyEvent
	deadline  time.Time
	maxDetail int
	effective EffectiveThrottle
}

type NotifyAggregator struct {
	mu      sync.Mutex
	buckets map[string]*aggBucket
	started bool
}

var NotifyAggregatorApp = &NotifyAggregator{
	buckets: make(map[string]*aggBucket),
}

// Add 把事件放进对应的桶；桶满或桶数量超限则立即刷新
func (a *NotifyAggregator) Add(sub model.NotifySubscription, channel model.NotifyChannel, ev NotifyEvent, d ThrottleDecision) {
	now := time.Now()
	var readyNow []*aggBucket

	a.mu.Lock()
	key := d.DedupKey
	bucket, ok := a.buckets[key]
	if !ok {
		bucket = &aggBucket{
			sub:       sub,
			channel:   channel,
			dedupKey:  d.DedupKey,
			deadline:  now.Add(time.Duration(d.Effective.AggregateWindowSec) * time.Second),
			maxDetail: d.Effective.AggregateMaxDetail,
			effective: d.Effective,
		}
		a.buckets[key] = bucket
	}
	bucket.events = append(bucket.events, ev)

	if len(bucket.events) >= aggBucketMaxEntries {
		readyNow = append(readyNow, bucket)
		delete(a.buckets, key)
	}
	if len(a.buckets) > aggMaxBuckets {
		zlog.Warn("通知聚合桶数量超限，强制全部刷新", "buckets", len(a.buckets))
		for k, b := range a.buckets {
			readyNow = append(readyNow, b)
			delete(a.buckets, k)
		}
	}
	a.mu.Unlock()

	for _, b := range readyNow {
		a.flushBucket(b)
	}
}

// StartFlushLoop 启动定时刷新（由消息队列引擎在启动时调用）
func (a *NotifyAggregator) StartFlushLoop(shutdown <-chan struct{}) {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return
	}
	a.started = true
	a.mu.Unlock()

	go a.loop(shutdown)
}

func (a *NotifyAggregator) loop(shutdown <-chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error(fmt.Sprintf("通知聚合器循环发生panic: %v，3秒后自动重启", r))
			time.Sleep(3 * time.Second)
			go a.loop(shutdown)
		}
	}()

	ticker := time.NewTicker(aggTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-shutdown:
			a.FlushAll()
			zlog.Info("通知聚合器收到关闭信号，已完成最终刷新")
			return
		case <-ticker.C:
			a.flushExpired()
		}
	}
}

// flushExpired 刷新已到窗口期的桶
func (a *NotifyAggregator) flushExpired() {
	now := time.Now()
	var ready []*aggBucket

	a.mu.Lock()
	for k, b := range a.buckets {
		if !now.Before(b.deadline) {
			ready = append(ready, b)
			delete(a.buckets, k)
		}
	}
	a.mu.Unlock()

	for _, b := range ready {
		a.flushBucket(b)
	}
}

// FlushAll 刷新全部桶（关闭前调用，保证缓冲中的通知不丢）
func (a *NotifyAggregator) FlushAll() {
	a.mu.Lock()
	ready := make([]*aggBucket, 0, len(a.buckets))
	for k, b := range a.buckets {
		ready = append(ready, b)
		delete(a.buckets, k)
	}
	a.mu.Unlock()

	for _, b := range ready {
		a.flushBucket(b)
	}
}

// flushBucket 把一个桶合并成一条通知发出去
func (a *NotifyAggregator) flushBucket(b *aggBucket) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error(fmt.Sprintf("通知聚合刷新发生panic: %v", r))
		}
	}()
	if b == nil || len(b.events) == 0 {
		return
	}
	WafNotifySenderServiceApp.DispatchEvents(b.sub, b.channel, b.events, b.dedupKey, b.maxDetail)
}

// BuildMergedMessage 把多条事件合并成一条通知的标题与正文
//
// 单条时保持与不聚合时逐字一致；多条时才加"（合并N条）"，与老实现的观感保持一致。
func BuildMergedMessage(sub model.NotifySubscription, channelType string, events []NotifyEvent, maxDetail int) (title, content, templateUsed string) {
	if len(events) == 0 {
		return "", "", model.TemplateUsedDefault
	}
	if len(events) == 1 {
		return RenderNotifyMessage(sub, channelType, events[0])
	}

	if maxDetail <= 0 {
		maxDetail = defaultAggregateMaxDetail
	}
	showCount := len(events)
	if showCount > maxDetail {
		showCount = maxDetail
	}

	firstTitle, _, used := RenderNotifyMessage(sub, channelType, events[0])
	title = firstTitle + "（合并" + strconv.Itoa(len(events)) + "条）"

	parts := make([]string, 0, showCount+1)
	for i := 0; i < showCount; i++ {
		_, body, u := RenderNotifyMessage(sub, channelType, events[i])
		if u == model.TemplateUsedFallback {
			used = model.TemplateUsedFallback
		}
		parts = append(parts, "**["+strconv.Itoa(i+1)+"]** "+body)
	}
	if len(events) > showCount {
		parts = append(parts, "\n...及其他 "+strconv.Itoa(len(events)-showCount)+" 条记录")
	}

	return title, strings.Join(parts, "\n\n---\n\n"), used
}
