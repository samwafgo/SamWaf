package waftunnelengine

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	ddnsMaxBindings   = 16
	ddnsMaxAddresses  = 16
	ddnsMaxResolvers  = 3
	ddnsMaxCNAME      = 8
	ddnsMaxAnswerRRs  = 256
	ddnsMaxTTL        = time.Hour
	ddnsFamilyTimeout = 5 * time.Second
	ddnsQueryTimeout  = 1200 * time.Millisecond
)

const (
	ddnsPending = "pending"
	ddnsActive  = "active"
	ddnsError   = "error"
	ddnsExpired = "expired"
	ddnsNoData  = "nodata"
	ddnsNX      = "nxdomain"
)

type ddnsAnswer struct {
	state string
	issue string
	ips   []netip.Addr
	until time.Time
}

func ddnsFailure(issue string) ddnsAnswer { return ddnsAnswer{state: ddnsError, issue: issue} }

type ddnsLookup func(context.Context, string, uint16) ddnsAnswer

type ddnsResolver struct {
	servers  []string
	now      func() time.Time
	exchange func(context.Context, *dns.Msg, string, string) (*dns.Msg, error)
}

func newDDNSResolver(config string) ddnsLookup {
	var servers []string
	if strings.TrimSpace(config) != "" {
		servers = ddnsEndpoints(strings.Split(config, ","))
	} else {
		servers = systemDDNSEndpoints()
	}
	return (&ddnsResolver{servers: servers, now: time.Now, exchange: exchangeDDNS}).lookup
}

func ddnsEndpoints(values []string) []string {
	var servers []string
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		var endpoint netip.AddrPort
		if ip, err := netip.ParseAddr(raw); err == nil {
			endpoint = netip.AddrPortFrom(ip.Unmap(), 53)
		} else if parsed, err := netip.ParseAddrPort(raw); err == nil {
			endpoint = netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port())
		}
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
			continue
		}
		server := endpoint.String()
		if !slices.Contains(servers, server) {
			servers = append(servers, server)
			if len(servers) >= ddnsMaxResolvers {
				break
			}
		}
	}
	return servers
}

func exchangeDDNS(ctx context.Context, query *dns.Msg, server, network string) (*dns.Msg, error) {
	client := dns.Client{Net: network, Timeout: ddnsQueryTimeout}
	conn, err := client.DialContext(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	answer, _, err := client.ExchangeWithConnContext(ctx, query, conn)
	return answer, err
}

func (r *ddnsResolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, time.Time, string) {
	issue := "resolver_unavailable"
	for _, server := range r.servers {
		if ctx.Err() != nil {
			return nil, time.Time{}, "timeout"
		}
		q := new(dns.Msg).SetQuestion(name, qtype)
		started := r.now()
		queryCtx, cancel := context.WithTimeout(ctx, ddnsQueryTimeout)
		answer, err := r.exchange(queryCtx, q, server, "udp")
		if err == nil && validDDNSReply(answer, q) && answer.Truncated {
			answer, err = r.exchange(queryCtx, q, server, "tcp")
		}
		cancel()
		if err != nil {
			issue = "query_failed"
			if e, ok := err.(net.Error); ok && e.Timeout() {
				issue = "timeout"
			}
			continue
		}
		if !validDDNSReply(answer, q) || answer.Truncated || len(answer.Answer)+len(answer.Ns) > ddnsMaxAnswerRRs {
			issue = "invalid_response"
			continue
		}
		switch answer.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return answer, started, ""
		case dns.RcodeServerFailure:
			issue = "servfail"
		case dns.RcodeRefused:
			issue = "refused"
		default:
			issue = "query_failed"
		}
	}
	return nil, time.Time{}, issue
}

func validDDNSReply(reply, q *dns.Msg) bool {
	if reply == nil || !reply.Response || reply.Id != q.Id || reply.Opcode != dns.OpcodeQuery || len(reply.Question) != 1 {
		return false
	}
	a, b := reply.Question[0], q.Question[0]
	return strings.EqualFold(a.Name, b.Name) && a.Qtype == b.Qtype && a.Qclass == b.Qclass
}

func ddnsName(value string) string {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) > 253 || !strings.Contains(value, ".") {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return value + "."
}

func (r *ddnsResolver) lookup(ctx context.Context, domain string, qtype uint16) ddnsAnswer {
	name := ddnsName(domain)
	if name == "" || (qtype != dns.TypeA && qtype != dns.TypeAAAA) {
		return ddnsFailure("invalid_domain")
	}
	ctx, cancel := context.WithTimeout(ctx, ddnsFamilyTimeout)
	defer cancel()
	var expires time.Time
	seen := map[string]bool{name: true}
	for {
		answer, started, issue := r.query(ctx, name, qtype)
		if answer == nil {
			return ddnsFailure(issue)
		}
		for {
			owner := ddnsOwnerAnswer(answer, name, qtype, started)
			if owner.invalid {
				return ddnsFailure("invalid_response")
			}
			if owner.target != "" {
				if seen[owner.target] || len(seen) > ddnsMaxCNAME {
					return ddnsFailure("cname_chain")
				}
				seen[owner.target] = true
				expires = ddnsEarliest(expires, owner.until)
				name = owner.target
				continue
			}
			if answer.Rcode == dns.RcodeNameError {
				if !owner.hasAddress && ddnsNegativeProof(answer, name) {
					return ddnsAnswer{state: ddnsNX}
				}
				return ddnsFailure("unconfirmed_negative")
			}
			if owner.hasAddress {
				expires = ddnsEarliest(expires, owner.until)
				if owner.oversized || len(owner.ips) == 0 || !expires.After(r.now()) {
					return ddnsAnswer{state: ddnsNoData}
				}
				slices.SortFunc(owner.ips, netip.Addr.Compare)
				return ddnsAnswer{state: ddnsActive, ips: owner.ips, until: expires}
			}
			if ddnsNegativeProof(answer, name) {
				return ddnsAnswer{state: ddnsNoData}
			}
			if strings.EqualFold(name, answer.Question[0].Name) {
				return ddnsFailure("unconfirmed_negative")
			}
			break // Chase only the target established by the answer section.
		}
	}
}

func ddnsNegativeProof(answer *dns.Msg, name string) bool {
	for _, rr := range answer.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && dns.IsSubDomain(strings.ToLower(soa.Hdr.Name), name) {
			return true
		}
	}
	return false
}

type ddnsOwnerRecords struct {
	target     string
	ips        []netip.Addr
	until      time.Time
	hasAddress bool
	invalid    bool
	oversized  bool
}

func ddnsOwnerAnswer(answer *dns.Msg, name string, qtype uint16, started time.Time) ddnsOwnerRecords {
	var result ddnsOwnerRecords
	for _, rr := range answer.Answer {
		hdr := rr.Header()
		if hdr.Class != dns.ClassINET || !strings.EqualFold(hdr.Name, name) {
			continue
		}
		ttl := min(ddnsMaxTTL, time.Duration(hdr.Ttl)*time.Second)
		if alias, ok := rr.(*dns.CNAME); ok {
			target := ddnsName(alias.Target)
			if target == "" || (result.target != "" && result.target != target) {
				return ddnsOwnerRecords{invalid: true}
			}
			result.target = target
			result.until = ddnsEarliest(result.until, started.Add(ttl))
			continue
		}
		if hdr.Rrtype != qtype {
			continue
		}
		var raw net.IP
		switch record := rr.(type) {
		case *dns.A:
			raw = record.A
		case *dns.AAAA:
			raw = record.AAAA
		default:
			continue
		}
		result.hasAddress = true
		result.until = ddnsEarliest(result.until, started.Add(ttl))
		addr, ok := netip.AddrFromSlice(raw)
		addr = addr.Unmap()
		if !ok || !isDDNSPublic(addr) || addr.Is4() != (qtype == dns.TypeA) || result.oversized {
			continue
		}
		if !slices.Contains(result.ips, addr) {
			if len(result.ips) == ddnsMaxAddresses {
				result.oversized = true
				continue
			}
			result.ips = append(result.ips, addr)
		}
	}
	result.invalid = result.target != "" && result.hasAddress
	return result
}

func ddnsEarliest(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

var ddnsIPv6Global = netip.MustParsePrefix("2000::/3")

var ddnsSpecialUse = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func isDDNSPublic(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || (addr.Is6() && !ddnsIPv6Global.Contains(addr)) {
		return false
	}
	for _, prefix := range ddnsSpecialUse {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
