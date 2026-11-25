//go:build !windows

package waftunnelengine

import (
	"net"

	"github.com/miekg/dns"
)

func systemDDNSEndpoints() []string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	endpoints := make([]string, 0, min(ddnsMaxResolvers, len(config.Servers)))
	for _, server := range config.Servers[:min(ddnsMaxResolvers, len(config.Servers))] {
		endpoints = append(endpoints, net.JoinHostPort(server, config.Port))
	}
	return ddnsEndpoints(endpoints)
}
