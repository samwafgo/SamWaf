package utils

import (
	"testing"

	"golang.org/x/net/idna"
)

func TestCanonicalHost_ASCIICase(t *testing.T) {
	if got := CanonicalHost("Example.COM"); got != "example.com" {
		t.Errorf("CanonicalHost(Example.COM)=%q", got)
	}
	if got := CanonicalHost("  WWW.Alias.COM.  "); got != "www.alias.com" {
		t.Errorf("CanonicalHost trim/dot=%q", got)
	}
	if CanonicalHost("*") != "*" {
		t.Errorf("catch-all * should stay")
	}
	if got := CanonicalHost("*.Example.COM"); got != "*.example.com" {
		t.Errorf("wildcard=%q", got)
	}
}

func TestCanonicalHost_IDN(t *testing.T) {
	puny, err := idna.Lookup.ToASCII("例子.com")
	if err != nil {
		t.Fatal(err)
	}
	if puny != "xn--fsqu00a.com" {
		t.Fatalf("unexpected punycode %q", puny)
	}
	if got := CanonicalHost("例子.com"); got != puny {
		t.Errorf("中文 → %q, want %q", got, puny)
	}
	if got := CanonicalHost(puny); got != puny {
		t.Errorf("puny 再归一 %q", got)
	}
	if got := CanonicalHost("*.例子.com"); got != "*."+puny {
		t.Errorf("中文泛域名 %q", got)
	}
}

func TestCanonicalRequestHost(t *testing.T) {
	hp, port := CanonicalRequestHost("Example.COM", false)
	if hp != "example.com:80" || port != "80" {
		t.Errorf("http default got %q port %q", hp, port)
	}
	hp, port = CanonicalRequestHost("例子.com", true)
	if hp != "xn--fsqu00a.com:443" || port != "443" {
		t.Errorf("https idn got %q port %q", hp, port)
	}
	hp, port = CanonicalRequestHost("Example.COM:8080", false)
	if hp != "example.com:8080" || port != "8080" {
		t.Errorf("explicit port got %q port %q", hp, port)
	}
}

func TestCanonicalHost_IP(t *testing.T) {
	if got := CanonicalHost("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("ipv4 %q", got)
	}
	if got := CanonicalHost("::1"); got != "::1" {
		t.Errorf("ipv6 %q", got)
	}
}
