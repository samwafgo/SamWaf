package waftunnelengine

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dnsRecord(t *testing.T, record string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(record)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestDDNSResolverFollowsOnlyAnswerChainAndConservesTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	start := now
	var calls []string
	r := ddnsResolver{servers: []string{"127.0.0.1:53"}, now: func() time.Time { return now }}
	r.exchange = func(_ context.Context, q *dns.Msg, _, _ string) (*dns.Msg, error) {
		name := q.Question[0].Name
		calls = append(calls, name)
		m := new(dns.Msg).SetReply(q)
		now = now.Add(2 * time.Second)
		switch name {
		case "binding.example.":
			m.Answer = []dns.RR{dnsRecord(t, "binding.example. 10 IN CNAME target.example."), dnsRecord(t, "unrelated.example. 0 IN A 1.1.1.1")}
			m.Extra = []dns.RR{dnsRecord(t, "target.example. 120 IN A 9.9.9.9")}
		case "target.example.":
			m.Answer = []dns.RR{dnsRecord(t, "TARGET.example. 60 IN A 8.8.4.4"), dnsRecord(t, "target.example. 60 IN A 8.8.4.4"), dnsRecord(t, "target.example. 120 IN A 192.0.2.42")}
		default:
			t.Fatalf("unexpected query %s", name)
		}
		return m, nil
	}
	answer := r.lookup(context.Background(), "Binding.Example.", dns.TypeA)
	if answer.state != ddnsActive || len(answer.ips) != 1 || answer.ips[0].String() != "8.8.4.4" || !answer.until.Equal(start.Add(10*time.Second)) {
		t.Fatalf("unexpected resolution: %+v", answer)
	}
	if !slices.Equal(calls, []string{"binding.example.", "target.example."}) {
		t.Fatalf("unexpected query chain: %v", calls)
	}
}

func TestDDNSResolverReplyClassification(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		name, state, issue string
		rcode              int
		answers, authority []string
		qtype              uint16
		lifetime           time.Duration
	}{
		{name: "public capped TTL", state: ddnsActive, answers: []string{"binding.example. 7200 IN A 8.8.4.4"}, lifetime: ddnsMaxTTL},
		{name: "zero TTL", state: ddnsNoData, answers: []string{"binding.example. 0 IN A 8.8.4.4"}},
		{name: "private and special use", state: ddnsNoData, answers: []string{"binding.example. 10 IN A 10.0.0.1", "binding.example. 10 IN A 100.64.0.1", "binding.example. 10 IN A 192.0.2.1", "binding.example. 10 IN A 240.0.0.1"}},
		{name: "public IPv6", state: ddnsActive, answers: []string{"binding.example. 20 IN AAAA 2606:4700::1111", "binding.example. 20 IN AAAA 2001:db8::123"}, qtype: dns.TypeAAAA, lifetime: 20 * time.Second},
		{name: "IPv6-only excludes mapped IPv4", state: ddnsNoData, answers: []string{"binding.example. 20 IN AAAA ::ffff:8.8.4.4"}, qtype: dns.TypeAAAA},
		{name: "confirmed absence", state: ddnsNX, rcode: dns.RcodeNameError, authority: []string{"example. 60 IN SOA ns.example. admin.example. 1 2 3 4 5"}},
		{name: "unrelated SOA", state: ddnsError, issue: "unconfirmed_negative", rcode: dns.RcodeNameError, authority: []string{"otherexample. 60 IN SOA ns.otherexample. admin.otherexample. 1 2 3 4 5"}},
		{name: "confirmed empty family", state: ddnsNoData, authority: []string{"example. 60 IN SOA ns.example. admin.example. 1 2 3 4 5"}},
		{name: "non-answer without SOA", state: ddnsError, issue: "unconfirmed_negative", answers: []string{"unrelated.example. 10 IN A 8.8.4.4"}},
		{name: "temporary failure", state: ddnsError, issue: "servfail", rcode: dns.RcodeServerFailure},
		{name: "CNAME loop", state: ddnsError, issue: "cname_chain", answers: []string{"binding.example. 10 IN CNAME target.example.", "target.example. 10 IN CNAME binding.example."}},
		{name: "CNAME conflict", state: ddnsError, issue: "invalid_response", answers: []string{"binding.example. 10 IN CNAME target.example.", "binding.example. 10 IN CNAME other.example."}},
		{name: "CNAME with ambiguous owner", state: ddnsError, issue: "invalid_response", answers: []string{"binding.example. 10 IN CNAME target.example.", "binding.example. 10 IN A 8.8.4.4"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ddnsResolver{servers: []string{"127.0.0.1:53"}, now: func() time.Time { return now }}
			r.exchange = func(_ context.Context, q *dns.Msg, _, _ string) (*dns.Msg, error) {
				m := new(dns.Msg).SetReply(q)
				m.Rcode = tc.rcode
				for _, record := range tc.answers {
					m.Answer = append(m.Answer, dnsRecord(t, record))
				}
				for _, record := range tc.authority {
					m.Ns = append(m.Ns, dnsRecord(t, record))
				}
				return m, nil
			}
			qtype := tc.qtype
			if qtype == 0 {
				qtype = dns.TypeA
			}
			answer := r.lookup(context.Background(), "binding.example", qtype)
			if answer.state != tc.state || answer.issue != tc.issue {
				t.Fatalf("got %+v, want %s %s", answer, tc.state, tc.issue)
			}
			if tc.lifetime > 0 && (len(answer.ips) != 1 || !answer.until.Equal(now.Add(tc.lifetime))) {
				t.Fatalf("unexpected IP set or TTL: %+v", answer)
			}
		})
	}
}

func TestDDNSResolverLimitsAndTruncatedFallback(t *testing.T) {
	if got := ddnsEndpoints([]string{"127.0.0.1", "127.0.0.1:53", "[::1]:1053"}); !slices.Equal(got, []string{"127.0.0.1:53", "[::1]:1053"}) {
		t.Fatalf("unexpected resolver endpoints: %v", got)
	}
	if got := ddnsEndpoints([]string{"127.0.0.1", "resolver.example", "::1"}); !slices.Equal(got, []string{"127.0.0.1:53", "[::1]:53"}) {
		t.Fatalf("invalid entries should be skipped, valid ones kept: %v", got)
	}
	if got := ddnsEndpoints([]string{"1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"}); !slices.Equal(got, []string{"1.0.0.1:53", "1.0.0.2:53", "1.0.0.3:53"}) {
		t.Fatalf("resolver list must be bounded: %v", got)
	}
	now := time.Unix(1000, 0)
	r := ddnsResolver{servers: []string{"127.0.0.1:53"}, now: func() time.Time { return now }}
	var networks []string
	r.exchange = func(_ context.Context, q *dns.Msg, _, network string) (*dns.Msg, error) {
		networks = append(networks, network)
		m := new(dns.Msg).SetReply(q)
		if network == "udp" {
			m.Truncated = true
			return m, nil
		}
		for i := 0; i <= ddnsMaxAddresses; i++ {
			m.Answer = append(m.Answer, dnsRecord(t, fmt.Sprintf("binding.example. 60 IN A 8.8.4.%d", i)))
		}
		return m, nil
	}
	if result := r.lookup(context.Background(), "binding.example", dns.TypeA); result.state != ddnsNoData || len(result.ips) != 0 || !slices.Equal(networks, []string{"udp", "tcp"}) {
		t.Fatalf("oversized answer or fallback mishandled: %+v, %v", result, networks)
	}
}

func TestDDNSResolverLoopbackDNS(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg).SetReply(q)
		m.RecursionAvailable = true
		if q.Question[0].Name == "binding.example." && q.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(8, 8, 4, 4)}}
		}
		_ = w.WriteMsg(m)
	})}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ActivateAndServe() }()
	defer conn.Close()
	select {
	case <-started:
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("loopback DNS server did not start")
	}
	defer server.Shutdown()
	result := newDDNSResolver(conn.LocalAddr().String())(context.Background(), "binding.example", dns.TypeA)
	if result.state != ddnsActive || len(result.ips) != 1 || result.ips[0].String() != "8.8.4.4" {
		t.Fatalf("loopback resolver: %+v", result)
	}
}
