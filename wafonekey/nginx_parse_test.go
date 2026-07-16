package wafonekey

import "testing"

func TestParseNginxText_Example(t *testing.T) {
	content := `
server
{
    listen 81;
    server_name log.samwaf.net log2.samwaf.net;
    index index.php index.html index.htm default.php default.htm default.html;
    root /www/wwwroot/log.samwaf.net_81;
    location / {
        root /some/other;
    }
}
server {
    listen 444 ssl http2;
    server_name shop.samwaf.net;
    ssl_certificate /x/a.pem;
    ssl_certificate_key /x/a.key;
    root /www/wwwroot/shop;
}
`
	got, err := ParseNginxText(content)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 candidates, got %d: %+v", len(got), got)
	}
	c0 := got[0]
	if c0.Port != 81 || c0.Ssl {
		t.Errorf("c0 port/ssl wrong: %+v", c0)
	}
	if len(c0.Domains) != 2 || c0.Domains[0] != "log.samwaf.net" || c0.Domains[1] != "log2.samwaf.net" {
		t.Errorf("c0 domains wrong: %+v", c0.Domains)
	}
	if c0.Root != "/www/wwwroot/log.samwaf.net_81" {
		t.Errorf("c0 root wrong: %q", c0.Root)
	}
	c1 := got[1]
	if c1.Port != 444 || !c1.Ssl {
		t.Errorf("c1 port/ssl wrong: %+v", c1)
	}
	if len(c1.Domains) != 1 || c1.Domains[0] != "shop.samwaf.net" {
		t.Errorf("c1 domains wrong: %+v", c1.Domains)
	}
}

func TestParseListen(t *testing.T) {
	cases := []struct {
		in   string
		port int
		ssl  bool
	}{
		{"81", 81, false},
		{"127.0.0.1:81", 81, false},
		{"[::]:81", 81, false},
		{"443 ssl http2", 443, true},
		{"0.0.0.0:443 ssl", 443, true},
	}
	for _, c := range cases {
		p, s := parseListen(c.in)
		if p != c.port || s != c.ssl {
			t.Errorf("parseListen(%q)=%d,%v want %d,%v", c.in, p, s, c.port, c.ssl)
		}
	}
}

func TestResolveSafeNginxDir(t *testing.T) {
	if _, err := resolveSafeNginxDir("/www/server/panel/vhost/nginx"); err != nil {
		t.Errorf("valid dir rejected: %v", err)
	}
	bad := []string{"/etc", "/root", "/tmp/server/panel/vhostEVIL/x", "/www/server/panel/../../../etc"}
	for _, d := range bad {
		if _, err := resolveSafeNginxDir(d); err == nil {
			t.Errorf("bad dir %q accepted", d)
		}
	}
}
