package waftunnelengine

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func testJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testBinding(id, family string) model.TunnelDDNSBinding {
	return model.TunnelDDNSBinding{ID: id, Domain: id + ".example", Family: family, Enabled: true}
}

func testTunnel(t *testing.T, id string, revision int64, bindings ...model.TunnelDDNSBinding) model.Tunnel {
	t.Helper()
	return model.Tunnel{BaseOrm: baseorm.BaseOrm{Id: id}, Port: "9112,9113", Protocol: "tcp", Code: "display-code",
		DDNSProtection: testJSON(t, model.TunnelDDNSProtection{Revision: revision, Bindings: bindings})}
}

func testRuntime(t *testing.T) (*ddnsRuntime, *ddnsRun) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	run := &ddnsRun{ctx: ctx, wake: make(chan struct{}, 1), audit: func(model.Tunnel, model.TunnelDDNSBinding, string, []string, []string) {}}
	return &ddnsRuntime{run: run}, run
}

func testSnapshot(t *testing.T, rt *ddnsRuntime, tunnelID string) *tunnelAccessPolicy {
	t.Helper()
	value, ok := rt.states.Load(tunnelID)
	if !ok {
		t.Fatal("no tunnel policy")
	}
	return value.(*tunnelProtectionRuntime).snapshot.Load()
}

func testAnswer(ip string, expiry time.Time) ddnsAnswer {
	return ddnsAnswer{state: ddnsActive, ips: []netip.Addr{netip.MustParseAddr(ip)}, until: expiry}
}

func testRound(t *testing.T, rt *ddnsRuntime, run *ddnsRun, now time.Time, binding string, answers ...ddnsAnswer) []ddnsAuditEvent {
	t.Helper()
	round, _, _ := rt.schedule(run, now, true)
	if round.binding == nil || round.binding.config.ID != binding {
		t.Fatalf("expected scheduled binding %s, got %+v", binding, round.binding)
	}
	copy(round.family[:], answers)
	return rt.finish(run, round, now)
}

func testReasons(t *testing.T, events []ddnsAuditEvent, want ...string) {
	t.Helper()
	var reasons []string
	for _, event := range events {
		reasons = append(reasons, event.reason)
	}
	if !slices.Equal(reasons, want) {
		t.Fatalf("audit reasons: got %v, want %v", reasons, want)
	}
}

func TestDDNSRuntimeDropsStaleRevisionUpdate(t *testing.T) {
	rt, _ := testRuntime(t)
	start := time.Unix(1000, 0)
	fresh := testTunnel(t, "x", 2, testBinding("b", "ipv4"))
	fresh.AllowIp = "1.1.1.1"
	rt.update(fresh, start)
	stale := testTunnel(t, "x", 1, testBinding("b", "ipv4"))
	stale.AllowIp = "2.2.2.2"
	rt.update(stale, start.Add(time.Second))
	policy := testSnapshot(t, rt, "x")
	if policy.tunnel.AllowIp != "1.1.1.1" || policy.tunnel.DDNSProtection != fresh.DDNSProtection {
		t.Fatalf("stale revision update must be dropped entirely: %+v", policy.tunnel)
	}
}

func TestDDNSRuntimeRetainsUntilOriginalExpiryAndRevokesFamilies(t *testing.T) {
	rt, run := testRuntime(t)
	start := time.Unix(1000, 0)
	tunnel := testTunnel(t, "x", 1, testBinding("dual", "both"))
	rt.update(tunnel, start)
	accept := func(now time.Time, addr string) bool {
		return testSnapshot(t, rt, tunnel.Id).denial(addr, now, tunnelCountry) == ""
	}
	if accept(start, "8.8.4.4") {
		t.Fatal("pending DDNS-only configuration must enforce whitelist")
	}
	expires4 := start.Add(30 * time.Second)
	expires6 := start.Add(120 * time.Second)
	events := testRound(t, rt, run, start, "dual", testAnswer("8.8.4.4", expires4), testAnswer("2606:4700::1111", expires6))
	testReasons(t, events, "addresses_changed")
	if !slices.Equal(events[0].after, []string{"2606:4700::1111", "8.8.4.4"}) || !accept(start, "::ffff:8.8.4.4") {
		t.Fatalf("first publish or canonical match failed: %+v", events)
	}
	if err := rt.refresh("x", "dual", 1, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	events = testRound(t, rt, run, start.Add(time.Second), "dual", ddnsFailure("timeout"), testAnswer("2606:4700::1111", expires6))
	testReasons(t, events, "resolution_error")
	status := rt.statuses("x", 1, start.Add(time.Second))[0]
	if status.State != "partial" || status.Families[0].State != ddnsError || status.Families[0].ValidUntil != ddnsTime(expires4) {
		t.Fatalf("unexpected transient status: %+v", status)
	}
	events = testRound(t, rt, run, start.Add(10*time.Second), "dual", ddnsFailure("servfail"), testAnswer("2606:4700::1111", expires6))
	testReasons(t, events)
	if !accept(expires4.Add(-time.Nanosecond), "8.8.4.4") || accept(expires4, "8.8.4.4") || !accept(expires4, "2606:4700::1111") {
		t.Fatal("the data plane must enforce independent original TTLs without a scheduler tick")
	}
	if s := rt.statuses("x", 1, expires4)[0]; s.Families[0].State != ddnsExpired || len(s.IPs) != 1 {
		t.Fatalf("incorrect TTL status before expiry sweep: %+v", s)
	}
	_, _, events = rt.schedule(run, expires4, false)
	testReasons(t, events, "expired")
	if !slices.Equal(events[0].before, []string{"2606:4700::1111", "8.8.4.4"}) || !slices.Equal(events[0].after, []string{"2606:4700::1111"}) {
		t.Fatalf("unexpected expiry event: %+v", events[0])
	}
	events = testRound(t, rt, run, expires4, "dual", ddnsAnswer{state: ddnsNoData}, testAnswer("2606:4700::1111", expires6))
	testReasons(t, events, "resolution_recovered")
	if err := rt.refresh("x", "dual", 1, expires4.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	events = testRound(t, rt, run, expires4.Add(time.Second), "dual", testAnswer("8.8.8.8", expires6), ddnsAnswer{state: ddnsNX})
	testReasons(t, events, "addresses_changed")
	if s := rt.statuses("x", 1, expires4.Add(time.Second))[0]; s.State != ddnsNX || len(s.IPs) != 0 || accept(expires4.Add(time.Second), "2606:4700::1111") {
		t.Fatalf("confirmed NXDOMAIN must revoke all families: %+v", s)
	}
}

func TestDDNSRuntimeDropsLateWorkAndKeepsUnrelatedConfirmations(t *testing.T) {
	rt, run := testRuntime(t)
	now := time.Unix(1000, 0)
	first, second := testBinding("first", "ipv4"), testBinding("second", "ipv4")
	tunnel := testTunnel(t, "x", 1, first)
	rt.update(tunnel, now)
	testRound(t, rt, run, now, "first", testAnswer("8.8.4.4", now.Add(time.Minute)))
	oldSnapshot := testSnapshot(t, rt, "x")
	tunnel.Port = "9114"
	tunnel.Code = "renamed"
	rt.update(tunnel, now)
	if s := rt.statuses("x", 1, now)[0]; !slices.Equal(s.IPs, []string{"8.8.4.4"}) {
		t.Fatalf("unrelated edits dropped confirmation: %+v", s)
	}
	other := testTunnel(t, "other", 1)
	other.Code = tunnel.Code
	rt.update(other, now)
	if p := testSnapshot(t, rt, "other"); len(p.dynamic) != 0 || p.whitelist {
		t.Fatal("tunnels with identical display codes must not share policy")
	}
	if err := rt.refresh("x", "first", 1, now); err != nil {
		t.Fatal(err)
	}
	late, ctx, _ := rt.schedule(run, now, true)
	next := testTunnel(t, "x", 2, first, second)
	rt.update(next, now)
	if ctx.Err() != context.Canceled || rt.statuses("x", 1, now) != nil || rt.refresh("x", "first", 1, now) == nil {
		t.Fatal("old revision did not cancel or remained available")
	}
	late.family[0] = testAnswer("8.8.8.8", now.Add(time.Hour))
	testReasons(t, rt.finish(run, late, now))
	if s := rt.statuses("x", 2, now)[0]; !slices.Equal(s.IPs, []string{"8.8.4.4"}) {
		t.Fatalf("late result replaced preserved confirmation: %+v", s)
	}
	first.Enabled = false
	rt.update(testTunnel(t, "x", 3, first, second), now)
	rt.update(next, now) // An older configuration notification cannot restore the binding.
	if s := rt.statuses("x", 3, now)[0]; s.State != "disabled" || len(s.IPs) > 0 || len(testSnapshot(t, rt, "x").dynamic) != 0 {
		t.Fatalf("disabled confirmation revived: %+v", s)
	}
	if !oldSnapshot.dynamic[netip.MustParseAddr("8.8.4.4")].After(now) {
		t.Fatal("updates must not mutate already published maps")
	}
	removed, ctx, _ := rt.schedule(run, now, true)
	rt.remove("x")
	if ctx.Err() != context.Canceled {
		t.Fatal("removing tunnel did not cancel query")
	}
	rt.update(testTunnel(t, "x", 3, first, second), now)
	removed.family[0] = testAnswer("8.8.8.8", now.Add(time.Hour))
	testReasons(t, rt.finish(run, removed, now))
	if s := rt.statuses("x", 3, now)[1]; s.State != ddnsPending || len(s.IPs) != 0 {
		t.Fatalf("removed tunnel result applied after re-creation: %+v", s)
	}
}

func TestDDNSAddressReplacementKeepsOtherSources(t *testing.T) {
	rt, run := testRuntime(t)
	now := time.Unix(1000, 0)
	first, second := testBinding("first", "ipv4"), testBinding("second", "ipv4")
	tunnel := testTunnel(t, "x", 1, first)
	tunnel.AllowIp = "9.9.9.9"
	rt.update(tunnel, now)
	testRound(t, rt, run, now, "first", testAnswer("8.8.4.4", now.Add(time.Minute)))
	tunnel.DDNSProtection = testJSON(t, model.TunnelDDNSProtection{Revision: 2, Bindings: []model.TunnelDDNSBinding{first, second}})
	rt.update(tunnel, now)
	testRound(t, rt, run, now, "second", testAnswer("8.8.4.4", now.Add(time.Hour)))
	if err := rt.refresh("x", "first", 2, now); err != nil {
		t.Fatal(err)
	}
	testReasons(t, testRound(t, rt, run, now, "first", testAnswer("8.8.8.8", now.Add(time.Hour))), "addresses_changed")
	p := testSnapshot(t, rt, "x")
	if !p.dynamic[netip.MustParseAddr("8.8.4.4")].Equal(now.Add(time.Hour)) || p.dynamic[netip.MustParseAddr("8.8.8.8")].IsZero() {
		t.Fatal("full RRset replacement discarded another binding's authorization")
	}
	tunnel.DDNSProtection = testJSON(t, model.TunnelDDNSProtection{Revision: 3, Bindings: []model.TunnelDDNSBinding{first}})
	rt.update(tunnel, now)
	p = testSnapshot(t, rt, "x")
	allow := func(ip string) bool {
		return p.denial(ip, now, tunnelCountry) == ""
	}
	if allow("8.8.4.4") || !allow("8.8.8.8") || !allow("9.9.9.9") {
		t.Fatal("old DNS address remained authorized or the configured union was not preserved")
	}
}

func TestDDNSManualRefreshBoundAndCooldown(t *testing.T) {
	rt, run := testRuntime(t)
	now := time.Unix(1000, 0)
	for i := 0; i < ddnsManualQueue+1; i++ {
		id := fmt.Sprintf("t%d", i)
		rt.update(testTunnel(t, id, 1, testBinding("binding", "ipv4")), now)
		if err := rt.refresh(id, "binding", 1, now); (err != nil) != (i == ddnsManualQueue) {
			t.Fatalf("unexpected queue result at %d: %v", i, err)
		}
	}
	if rt.refresh("t0", "binding", 1, now) == nil {
		t.Fatal("duplicate queued request accepted")
	}
	rt.remove("t0")
	if err := rt.refresh(fmt.Sprintf("t%d", ddnsManualQueue), "binding", 1, now); err != nil {
		t.Fatalf("queue slot not released by removal: %v", err)
	}
	round, _, _ := rt.schedule(run, now, true)
	if round.binding == nil {
		t.Fatal("expected pending query")
	}
	id := round.state.policy.tunnel.Id
	round.family[0] = ddnsAnswer{state: ddnsNoData}
	rt.finish(run, round, now)
	if rt.refresh(id, "binding", 1, now.Add(ddnsManualMin-time.Nanosecond)) == nil {
		t.Fatal("manual cooldown did not apply")
	}
	if err := rt.refresh(id, "binding", 1, now.Add(ddnsManualMin)); err != nil {
		t.Fatalf("manual cooldown did not reset: %v", err)
	}
}

func TestDDNSRuntimeLifecycleWaitsForResolver(t *testing.T) {
	var rt ddnsRuntime
	now := time.Now()
	tunnel := testTunnel(t, "x", 1, testBinding("binding", "ipv4"))
	rt.update(tunnel, now)
	started, stopped := make(chan struct{}), make(chan struct{})
	if rt.refresh("x", "binding", 1, now) == nil {
		t.Fatal("standby cannot trigger resolution")
	}
	rt.start(func(ctx context.Context, _ string, _ uint16) ddnsAnswer {
		close(started)
		<-ctx.Done()
		close(stopped)
		return ddnsFailure("timeout")
	}, nil)
	t.Cleanup(rt.stop)
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not schedule first lookup")
	}
	rt.stop()
	select {
	case <-stopped:
	default:
		t.Fatal("shutdown returned before resolver exited")
	}
	if rt.statuses("x", 1, now) != nil {
		t.Fatal("shutdown retained runtime state")
	}
}
