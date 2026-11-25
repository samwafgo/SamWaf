package waftunnelengine

import (
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestDDNSWindowsDiscoverySkipsDNSPlaceholdersBeforeLimit(t *testing.T) {
	var servers *windows.IpAdapterDnsServerAdapter
	for _, text := range []string{"fec0:0:0:ffff::3", "fec0:0:0:ffff::2", "fec0:0:0:ffff::1"} {
		storage := new(syscall.RawSockaddrAny)
		addr := (*syscall.RawSockaddrInet6)(unsafe.Pointer(storage))
		*addr = syscall.RawSockaddrInet6{Family: syscall.AF_INET6, Addr: netip.MustParseAddr(text).As16()}
		servers = &windows.IpAdapterDnsServerAdapter{
			Next: servers,
			Address: windows.SocketAddress{
				Sockaddr:       storage,
				SockaddrLength: int32(unsafe.Sizeof(*addr)),
			},
		}
	}
	storage := new(syscall.RawSockaddrAny)
	resolver := (*syscall.RawSockaddrInet4)(unsafe.Pointer(storage))
	*resolver = syscall.RawSockaddrInet4{Family: syscall.AF_INET, Addr: [4]byte{192, 168, 0, 53}}
	configured := &windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{
		Sockaddr:       storage,
		SockaddrLength: int32(unsafe.Sizeof(*resolver)),
	}}
	adapters := &windows.IpAdapterAddresses{
		OperStatus:            windows.IfOperStatusUp,
		FirstDnsServerAddress: servers,
		Next: &windows.IpAdapterAddresses{
			OperStatus:            windows.IfOperStatusUp,
			FirstDnsServerAddress: configured,
		},
	}
	if got := windowsAdapterDDNSEndpoints(adapters); !slices.Equal(got, []string{"192.168.0.53:53"}) {
		t.Fatalf("discovered DNS endpoints = %v, want the configured resolver", got)
	}
}
