package waf_service

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"strings"
	"testing"
)

func TestAttackNotifyEventDomain(t *testing.T) {
	for _, tc := range []struct {
		name, domain, url, want string
	}{
		{"relative URL", "site.example", "/test?a=1", "site.example"},
		{"engine HTTP host", "http://site.example", "/test", "site.example"},
		{"engine HTTPS host", "https://site.example", "/test", "site.example"},
		{"engine websocket host", "wss://[2001:db8::1]:8080", "/test", "[2001:db8::1]:8080"},
		{"explicit host", "site.example:8080", "https://other.example/test", "site.example:8080"},
		{"IPv6", "[2001:db8::1]:8080", "/test", "[2001:db8::1]:8080"},
		{"URL fallback", "", "https://site.example/test", "site.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.AttackInfoMessageInfo{
				Domain: tc.domain, AttackType: "SQL注入", Url: tc.url,
				Ip: "192.0.2.10", Time: "2026-11-11 12:00:00",
			})
			if ev.MessageType != model.MSG_TYPE_ATTACK_INFO || ev.Severity != model.SeverityCritical {
				t.Fatalf("unexpected category/severity: %s/%s", ev.MessageType, ev.Severity)
			}
			if ev.Vars["Domain"] != tc.want || ev.DedupParts[model.DedupKeyDomain] != tc.want {
				t.Fatalf("domain vars=%q dedup=%q, want %q", ev.Vars["Domain"], ev.DedupParts[model.DedupKeyDomain], tc.want)
			}
			if !MatchNotifyFilter(model.NotifyFilterConfig{Domains: []string{tc.want}}, ev) ||
				MatchNotifyFilter(model.NotifyFilterConfig{Domains: []string{"unrelated.example"}}, ev) {
				t.Fatal("domain filter did not select the event's site")
			}
			if MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"192.0.2.0/24"}}, ev) {
				t.Fatal("excluded source IP passed the filter")
			}
			if ev.Vars["Time"] != "2026-11-11 12:00:00" || ev.Vars["Url"] != tc.url {
				t.Fatal("event time or URL changed")
			}
			if tc.domain != "" && !strings.Contains(ev.DefaultContent, tc.domain) {
				t.Fatal("default content does not identify the site")
			}
		})
	}
}

func TestAttackNotifyCooldownSeparatesSites(t *testing.T) {
	WafNotifyThrottleServiceApp.ResetAll()
	t.Cleanup(WafNotifyThrottleServiceApp.ResetAll)
	sub := newTestSub("attack-site", model.MSG_TYPE_ATTACK_INFO, model.ThrottleModeCooldown,
		model.NotifyThrottleConfig{CooldownStepsSec: []int{60}})
	for _, domain := range []string{"first.example", "second.example"} {
		ev := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.AttackInfoMessageInfo{
			Domain: domain, AttackType: "SQL注入", Url: "/test", Ip: "192.0.2.10",
		})
		d := WafNotifyThrottleServiceApp.Decide(sub, ev)
		if d.Action != ThrottleActionSend {
			t.Fatalf("first event for %s = %s, want send", domain, d.Action)
		}
		WafNotifyThrottleServiceApp.NoteSent(d.DedupKey)
		if repeat := WafNotifyThrottleServiceApp.Decide(sub, ev); repeat.Action != ThrottleActionSuppress {
			t.Fatalf("repeat event for %s = %s, want suppress", domain, repeat.Action)
		}
	}
}

func TestAttackNotifyPreviewMatchesDefault(t *testing.T) {
	sample := SampleNotifyEvent(model.MSG_TYPE_ATTACK_INFO)
	real := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.AttackInfoMessageInfo{
		Domain: sample.Vars["Domain"], AttackType: sample.Vars["AttackType"],
		Url: sample.Vars["Url"], Ip: sample.Vars["Ip"], Time: sample.Vars["Time"],
	})
	if sample.DefaultTitle != real.DefaultTitle || sample.DefaultContent != real.DefaultContent {
		t.Fatal("preview and real default messages differ")
	}
}
