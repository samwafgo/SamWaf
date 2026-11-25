package waftunnelengine

import (
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemDDNSEndpoints() []string {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(15 * 1024)
	for retries := 0; retries < 3 && size <= 1024*1024; retries++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		switch windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size) {
		case windows.ERROR_BUFFER_OVERFLOW:
			continue
		case nil:
		default:
			return nil
		}
		endpoints := windowsAdapterDDNSEndpoints(first)
		runtime.KeepAlive(buffer)
		return endpoints
	}
	return nil
}

// Windows can report these legacy IPv6 DNS placeholders on active adapters.
var windowsDNSPlaceholders = []netip.Addr{
	netip.MustParseAddr("fec0:0:0:ffff::1"),
	netip.MustParseAddr("fec0:0:0:ffff::2"),
	netip.MustParseAddr("fec0:0:0:ffff::3"),
}

func windowsAdapterDDNSEndpoints(first *windows.IpAdapterAddresses) []string {
	var endpoints []string
	for adapter := first; adapter != nil && len(endpoints) < ddnsMaxResolvers; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for server := adapter.FirstDnsServerAddress; server != nil && len(endpoints) < ddnsMaxResolvers; server = server.Next {
			ip, ok := netip.AddrFromSlice(server.Address.IP())
			ip = ip.Unmap()
			if !ok || ip.IsUnspecified() || ip.IsMulticast() || slices.Contains(windowsDNSPlaceholders, ip) {
				continue
			}
			if ip.IsLinkLocalUnicast() && ip.Is6() {
				ip = ip.WithZone(strconv.FormatUint(uint64(adapter.Ipv6IfIndex), 10))
			}
			endpoint := ip.String()
			if !slices.Contains(endpoints, endpoint) {
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	return ddnsEndpoints(endpoints)
}
