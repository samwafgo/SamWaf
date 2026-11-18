package validfield

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	OriginalRequestHost     = "${host}"
	OriginalRequestHostname = "${hostname}"
)

var requestHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?$`)

// ValidRequestHost checks a concrete Host value, with an optional port.
func ValidRequestHost(value string) bool {
	if len(value) == 0 || len(value) > 260 {
		return false
	}

	host := value
	if strings.Contains(value, ":") && !(strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")) {
		name, port, err := net.SplitHostPort(value)
		n, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || len(port) > 5 || n == 0 {
			return false
		}
		host = name
		if strings.HasPrefix(value, "[") {
			return validIPv6RequestHost(host)
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return validIPv6RequestHost(host[1 : len(host)-1])
	}
	return len(host) <= 254 && requestHostnamePattern.MatchString(host)
}

func validIPv6RequestHost(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is6() && ip.Zone() == ""
}
