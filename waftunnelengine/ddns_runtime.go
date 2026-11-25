package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	ddnsWorkers         = 4
	ddnsManualQueue     = 64
	ddnsAuditQueue      = 128
	ddnsDispatch        = 250 * time.Millisecond
	ddnsMinRefresh      = 5 * time.Second
	ddnsManualMin       = 10 * time.Second
	ddnsNegativeRefresh = time.Minute
)

var ddnsTypes = [2]uint16{dns.TypeA, dns.TypeAAAA}
var ddnsFamilies = [2]string{"ipv4", "ipv6"}

type tunnelProtectionRuntime struct {
	snapshot       atomic.Pointer[tunnelAccessPolicy]
	policy         tunnelAccessPolicy
	regionRevision int64
	ddnsRevision   int64
	invalidDDNS    bool
	bindings       []*ddnsBindingRuntime
}

type ddnsBindingRuntime struct {
	config     model.TunnelDDNSBinding
	family     [2]ddnsAnswer
	next       time.Time
	lastManual time.Time
	checked    time.Time
	cancel     context.CancelFunc
	manual     bool
	failures   int
}

func (b *ddnsBindingRuntime) selects(i int) bool {
	return b.config.Family == "both" || b.config.Family == ddnsFamilies[i]
}

func (b *ddnsBindingRuntime) ips() []string {
	ips := make([]string, 0)
	for i := range b.family {
		for _, ip := range b.family[i].ips {
			ips = append(ips, ip.String())
		}
	}
	slices.Sort(ips)
	return slices.Compact(ips)
}

type ddnsAuditEvent struct {
	tunnel        model.Tunnel
	binding       model.TunnelDDNSBinding
	reason        string
	before, after []string
}

type ddnsRound struct {
	state    *tunnelProtectionRuntime
	binding  *ddnsBindingRuntime
	revision int64
	family   [2]ddnsAnswer
}

type ddnsRun struct {
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	wake         chan struct{}
	results      chan ddnsRound
	lookup       ddnsLookup
	audit        func(model.Tunnel, model.TunnelDDNSBinding, string, []string, []string)
	auditEvents  chan ddnsAuditEvent
	nextAuditLog time.Time
}

// Mutable scheduler state is protected by mu; listeners only load immutable snapshots.
type ddnsRuntime struct {
	mu           sync.Mutex
	states       sync.Map // Tunnel.Id → *tunnelProtectionRuntime
	working      map[*tunnelProtectionRuntime]struct{}
	run          *ddnsRun
	manualQueued int
}

func decodeTunnelProtection[T any](raw string, value *T) bool {
	return raw == "" || len(raw) <= 64*1024 && raw[0] == '{' && json.Unmarshal([]byte(raw), value) == nil
}

func (rt *ddnsRuntime) update(tunnel model.Tunnel, now time.Time) {
	var region model.TunnelRegionProtection
	var config model.TunnelDDNSProtection
	badRegion := !decodeTunnelProtection(tunnel.RegionProtection, &region)
	badDDNS := !decodeTunnelProtection(tunnel.DDNSProtection, &config) || len(config.Bindings) > ddnsMaxBindings

	rt.mu.Lock()
	defer rt.mu.Unlock()
	candidate, _ := rt.states.LoadOrStore(tunnel.Id, &tunnelProtectionRuntime{})
	state := candidate.(*tunnelProtectionRuntime)
	old := state.policy.tunnel
	if (!badRegion && region.Revision < state.regionRevision) || (!badDDNS && config.Revision < state.ddnsRevision) {
		// 迟到消息的保护配置修订低于当前状态，整条更新丢弃，避免旧名单配新修订
		return
	}
	if !badRegion {
		state.regionRevision = region.Revision
	}
	if !badDDNS && (state.snapshot.Load() == nil || old.DDNSProtection != tunnel.DDNSProtection) {
		prior := make(map[string]*ddnsBindingRuntime, len(state.bindings))
		for _, binding := range state.bindings {
			prior[binding.config.ID] = binding
			rt.cancelBinding(binding)
		}
		state.bindings = nil
		if !badDDNS {
			for _, cfg := range config.Bindings {
				binding := &ddnsBindingRuntime{config: cfg, next: now}
				oldBinding := prior[cfg.ID]
				if oldBinding != nil && oldBinding.config == cfg {
					binding.family = oldBinding.family
					binding.checked = oldBinding.checked
					binding.failures = oldBinding.failures
					binding.lastManual = oldBinding.lastManual
					if oldBinding.cancel == nil && !oldBinding.manual {
						binding.next = oldBinding.next
					}
				}
				state.bindings = append(state.bindings, binding)
			}
		}
		state.ddnsRevision = config.Revision
	}
	state.invalidDDNS = badDDNS
	dynamicEnabled := false
	for _, binding := range state.bindings {
		if binding.config.Enabled {
			dynamicEnabled = true
			break
		}
	}
	if dynamicEnabled {
		if rt.working == nil {
			rt.working = make(map[*tunnelProtectionRuntime]struct{})
		}
		rt.working[state] = struct{}{}
	} else {
		delete(rt.working, state)
	}
	state.policy = tunnelAccessPolicy{
		tunnel: tunnel, region: region, invalidRegion: badRegion,
		enhanced:  region.Enabled || badRegion || dynamicEnabled || badDDNS,
		whitelist: dynamicEnabled || badDDNS || tunnel.AllowIp != "",
	}
	if state.policy.enhanced {
		state.policy.allow = tunnelPrefixes(tunnel.AllowIp)
		state.policy.deny = tunnelPrefixes(tunnel.DenyIp)
	}
	state.publish()
	rt.wakeLocked()
}

func (state *tunnelProtectionRuntime) publish() {
	policy := state.policy
	for _, binding := range state.bindings {
		if !binding.config.Enabled {
			continue
		}
		for _, family := range binding.family {
			for _, ip := range family.ips {
				if policy.dynamic == nil {
					policy.dynamic = make(map[netip.Addr]time.Time)
				}
				if family.until.After(policy.dynamic[ip]) {
					policy.dynamic[ip] = family.until
				}
			}
		}
	}
	state.snapshot.Store(&policy)
}

func (rt *ddnsRuntime) remove(id string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if value, exists := rt.states.LoadAndDelete(id); exists {
		state := value.(*tunnelProtectionRuntime)
		delete(rt.working, state)
		state.snapshot.Store(nil)
		for _, binding := range state.bindings {
			rt.cancelBinding(binding)
		}
	}
}

func (rt *ddnsRuntime) cancelBinding(binding *ddnsBindingRuntime) {
	if binding.manual {
		rt.manualQueued--
	}
	if binding.cancel != nil {
		binding.cancel()
	}
}

func (rt *ddnsRuntime) start(lookup ddnsLookup, audit func(model.Tunnel, model.TunnelDDNSBinding, string, []string, []string)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.run != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &ddnsRun{ctx: ctx, cancel: cancel, lookup: lookup, audit: audit,
		done: make(chan struct{}), wake: make(chan struct{}, 1), results: make(chan ddnsRound, ddnsWorkers)}
	if audit != nil {
		run.auditEvents = make(chan ddnsAuditEvent, ddnsAuditQueue)
	}
	rt.run = run
	go rt.runLoop(run)
}

func (rt *ddnsRuntime) stop() {
	rt.mu.Lock()
	run := rt.run
	rt.run = nil
	if run != nil {
		run.cancel()
	}
	rt.states.Range(func(key, value any) bool {
		value.(*tunnelProtectionRuntime).snapshot.Store(nil)
		rt.states.Delete(key)
		return true
	})
	rt.working = nil
	rt.manualQueued = 0
	rt.mu.Unlock()
	if run != nil {
		<-run.done
	}
}

func (rt *ddnsRuntime) wakeLocked() {
	if rt.run != nil {
		select {
		case rt.run.wake <- struct{}{}:
		default:
		}
	}
}

func (rt *ddnsRuntime) runLoop(run *ddnsRun) {
	defer close(run.done)
	var work sync.WaitGroup
	defer work.Wait()
	if run.auditEvents != nil {
		work.Go(run.auditLoop)
	}
	ticker := time.NewTicker(ddnsDispatch)
	defer ticker.Stop()
	var nextLaunch time.Time
	active := 0
	for run.ctx.Err() == nil {
		now := time.Now()
		round, ctx, events := rt.schedule(run, now, active < ddnsWorkers && !now.Before(nextLaunch))
		if round.binding != nil {
			active++
			nextLaunch = now.Add(ddnsDispatch)
			work.Go(func() {
				round.resolve(ctx, run.lookup)
				select {
				case run.results <- round:
				case <-run.ctx.Done():
				}
			})
		}
		run.emit(events)
		select {
		case <-run.ctx.Done():
			return
		case <-run.wake:
		case <-ticker.C:
		case result := <-run.results:
			active--
			run.emit(rt.finish(run, result, time.Now()))
		}
	}
}

func (round *ddnsRound) resolve(ctx context.Context, lookup ddnsLookup) {
	b := round.binding
	var families sync.WaitGroup
	for i, qtype := range ddnsTypes {
		if b.selects(i) {
			families.Go(func() { round.family[i] = lookup(ctx, b.config.Domain, qtype) })
		}
	}
	families.Wait()
}

func (run *ddnsRun) emit(events []ddnsAuditEvent) {
	if run.auditEvents == nil {
		return
	}
	for _, event := range events {
		select {
		case <-run.ctx.Done():
			return
		case run.auditEvents <- event:
		default:
			if now := time.Now(); !now.Before(run.nextAuditLog) {
				run.nextAuditLog = now.Add(time.Minute)
				zlog.Warn("隧道域名解析审计队列已满，部分事件未记录")
			}
		}
	}
}

func (run *ddnsRun) auditLoop() {
	for {
		select {
		case <-run.ctx.Done():
			return
		case event := <-run.auditEvents:
			if run.ctx.Err() != nil {
				return
			}
			run.audit(event.tunnel, event.binding, event.reason, event.before, event.after)
		}
	}
}

func (rt *ddnsRuntime) schedule(run *ddnsRun, now time.Time, dispatch bool) (ddnsRound, context.Context, []ddnsAuditEvent) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.run != run {
		return ddnsRound{}, nil, nil
	}
	var chosen ddnsRound
	var events []ddnsAuditEvent
	for state := range rt.working {
		changed := false
		for _, binding := range state.bindings {
			if !binding.config.Enabled {
				continue
			}
			if event, expired := expireDDNSBinding(state, binding, now, run.audit != nil); expired {
				changed = true
				if event.reason != "" {
					events = append(events, event)
				}
			}
			if dispatch && binding.cancel == nil && !now.Before(binding.next) && (chosen.binding == nil || binding.next.Before(chosen.binding.next)) {
				chosen = ddnsRound{state: state, binding: binding, revision: state.ddnsRevision}
			}
		}
		if changed {
			state.publish()
		}
	}
	var ctx context.Context
	if b := chosen.binding; b != nil {
		ctx, b.cancel = context.WithCancel(run.ctx)
		if b.manual {
			rt.manualQueued--
			b.manual = false
		}
	}
	return chosen, ctx, events
}

func expireDDNSBinding(state *tunnelProtectionRuntime, b *ddnsBindingRuntime, now time.Time, audit bool) (ddnsAuditEvent, bool) {
	var previous []string
	expired := false
	for i := range b.family {
		family := &b.family[i]
		if len(family.ips) != 0 && !now.Before(family.until) {
			if !expired && audit {
				previous = b.ips()
			}
			expired = true
			family.ips = nil
			family.until = time.Time{}
			family.state = ddnsExpired
		}
	}
	if expired && audit {
		return ddnsAuditEvent{state.policy.tunnel, b.config, "expired", previous, b.ips()}, true
	}
	return ddnsAuditEvent{}, expired
}

func (rt *ddnsRuntime) finish(run *ddnsRun, round ddnsRound, now time.Time) []ddnsAuditEvent {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	state, b := round.state, round.binding
	if rt.run != run || state.snapshot.Load() == nil || state.ddnsRevision != round.revision || !slices.Contains(state.bindings, b) {
		return nil
	}
	b.cancel()
	b.cancel = nil
	var events []ddnsAuditEvent
	auditing := run.audit != nil
	if event, _ := expireDDNSBinding(state, b, now, auditing); event.reason != "" {
		events = append(events, event)
	}
	var previous []string
	if auditing {
		previous = b.ips()
	}
	wasFailing := b.failures != 0
	nx := false
	softError := false
	var earliest time.Time
	for _, answer := range round.family {
		if answer.state == ddnsNX {
			nx = true
		}
	}
	for i, answer := range round.family {
		if !b.selects(i) {
			continue
		}
		if nx {
			answer = ddnsAnswer{state: ddnsNX}
		} else if answer.state == ddnsError {
			softError = true
			answer.ips = b.family[i].ips
			answer.until = b.family[i].until
		} else if answer.state == ddnsActive && !now.Before(answer.until) {
			answer = ddnsAnswer{state: ddnsNoData}
		}
		b.family[i] = answer
		if answer.state == ddnsActive {
			earliest = ddnsEarliest(earliest, answer.until)
		}
	}
	b.checked = now
	delay := ddnsNegativeRefresh
	if !earliest.IsZero() {
		duration := earliest.Sub(now)
		delay = duration * time.Duration(70+rand.IntN(16)) / 100
	}
	if softError {
		b.failures = min(b.failures+1, 6)
		backoff := min(2*time.Minute, ddnsMinRefresh<<uint(b.failures-1))
		delay = min(delay, backoff)
		if earliest.IsZero() {
			delay = backoff
		}
	} else {
		b.failures = 0
	}
	b.next = now.Add(max(ddnsMinRefresh, delay))
	state.publish()
	if auditing {
		current := b.ips()
		if !slices.Equal(previous, current) {
			events = append(events, ddnsAuditEvent{state.policy.tunnel, b.config, "addresses_changed", previous, current})
		}
		if wasFailing != softError {
			reason := "resolution_error"
			if !softError {
				reason = "resolution_recovered"
			}
			events = append(events, ddnsAuditEvent{state.policy.tunnel, b.config, reason, previous, current})
		}
	}
	return events
}

func (waf *WafTunnelEngine) RefreshDDNS(tunnelID, bindingID string, revision int64) error {
	return waf.ddns.refresh(tunnelID, bindingID, revision, time.Now())
}

func (rt *ddnsRuntime) refresh(tunnelID, bindingID string, revision int64, now time.Time) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.run == nil {
		return errors.New("隧道引擎尚未就绪，请稍后重试")
	}
	value, exists := rt.states.Load(tunnelID)
	if !exists || value.(*tunnelProtectionRuntime).ddnsRevision != revision {
		return errors.New("动态域名配置正在同步，请稍后重试")
	}
	state := value.(*tunnelProtectionRuntime)
	for _, b := range state.bindings {
		if b.config.ID != bindingID || !b.config.Enabled {
			continue
		}
		if b.manual || b.cancel != nil || now.Before(b.lastManual.Add(ddnsManualMin)) {
			return errors.New("解析请求过于频繁，请稍后重试")
		}
		if rt.manualQueued >= ddnsManualQueue {
			return errors.New("解析队列已满，请稍后重试")
		}
		b.manual = true
		b.lastManual = now
		rt.manualQueued++
		b.next = ddnsEarliest(b.next, now)
		rt.wakeLocked()
		return nil
	}
	return errors.New("未找到已启用的动态域名绑定")
}

func (waf *WafTunnelEngine) DDNSStatuses(tunnelID string, revision int64) []model.TunnelDDNSStatus {
	return waf.ddns.statuses(tunnelID, revision, time.Now())
}

func (rt *ddnsRuntime) statuses(tunnelID string, revision int64, now time.Time) []model.TunnelDDNSStatus {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	value, exists := rt.states.Load(tunnelID)
	if !exists || value.(*tunnelProtectionRuntime).ddnsRevision != revision {
		return nil
	}
	state := value.(*tunnelProtectionRuntime)
	statuses := make([]model.TunnelDDNSStatus, 0, len(state.bindings))
	for _, b := range state.bindings {
		status := model.TunnelDDNSStatus{BindingID: b.config.ID, State: "disabled", IPs: []string{}}
		if b.config.Enabled {
			status.State = ddnsPending
			status.LastCheck = ddnsTime(b.checked)
			var earliest time.Time
			var first string
			for i, family := range b.family {
				if !b.selects(i) {
					continue
				}
				entry := model.TunnelDDNSFamilyStatus{Family: ddnsFamilies[i], State: family.state, Error: family.issue,
					LastCheck: status.LastCheck, IPs: []string{}}
				if entry.State == "" {
					entry.State = ddnsPending
				}
				if !family.until.IsZero() && !now.Before(family.until) {
					entry.State = ddnsExpired
				} else if len(family.ips) != 0 {
					entry.ValidUntil = ddnsTime(family.until)
					earliest = ddnsEarliest(earliest, family.until)
					for _, ip := range family.ips {
						entry.IPs = append(entry.IPs, ip.String())
					}
					status.IPs = append(status.IPs, entry.IPs...)
				}
				if first == "" {
					first = entry.State
				}
				if status.Error == "" {
					status.Error = entry.Error
				}
				status.Families = append(status.Families, entry)
			}
			status.ValidUntil = ddnsTime(earliest)
			status.State = ddnsAggregateStatus(status.Families, first, len(status.IPs) != 0)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func ddnsAggregateStatus(families []model.TunnelDDNSFamilyStatus, first string, hasIPs bool) string {
	if len(families) == 0 {
		return ddnsError
	}
	if len(families) == 1 || first == families[1].State {
		return first
	}
	if hasIPs {
		return "partial"
	}
	for _, candidate := range []string{ddnsError, ddnsExpired, ddnsPending, ddnsNX, ddnsNoData} {
		if first == candidate || families[1].State == candidate {
			return candidate
		}
	}
	return first
}

func ddnsTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
