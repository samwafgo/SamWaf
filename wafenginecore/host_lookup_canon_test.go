package wafenginecore

import (
	"SamWaf/common/domaintool"
	"SamWaf/model"
	"SamWaf/utils"
	"crypto/tls"
	"testing"

	"golang.org/x/net/idna"
)

func lookupCode(waf *WafEngine, requestHost string, tlsReq bool) string {
	host, _ := utils.CanonicalRequestHost(requestHost, tlsReq)
	if targetHost, ok := waf.rt().HostTargetNoPort[utils.CanonicalHost(utils.GetPureDomain(host))]; ok {
		host = targetHost
	}
	if target, ok := waf.rt().HostTarget[host]; ok {
		return target.Host.Code
	}
	if target, ok := waf.rt().HostTarget[domaintool.MaskSubdomain(host)]; ok {
		return target.Host.Code
	}
	if code, ok := waf.rt().HostTargetMoreDomain[host]; ok {
		return code
	}
	if code, ok := waf.rt().HostTargetMoreDomain[domaintool.MaskSubdomain(host)]; ok {
		return code
	}
	return ""
}

func TestHostLookup_CaseInsensitiveAndIDN(t *testing.T) {
	puny, err := idna.Lookup.ToASCII("例子.com")
	if err != nil {
		t.Fatal(err)
	}
	waf := newTestWafEngine()
	simulateLoadHostMaps(waf, model.Hosts{Code: "c1", Host: "Example.COM", Port: 80})
	if lookupCode(waf, "example.com", false) != "c1" {
		t.Fatal("大小写应命中同一站点")
	}
	if lookupCode(waf, "EXAMPLE.com", false) != "c1" {
		t.Fatal("请求大写也应命中")
	}

	waf2 := newTestWafEngine()
	simulateLoadHostMaps(waf2, model.Hosts{Code: "idn", Host: "例子.com", Port: 80})
	if lookupCode(waf2, puny, false) != "idn" {
		t.Fatalf("中文绑定应对 Punycode Host 命中，key=%v", waf2.rt().HostTarget)
	}
	if lookupCode(waf2, "例子.com", false) != "idn" {
		t.Fatal("中文 Host 也应命中")
	}
}

func TestHostOverlap_BindMoreHostDoesNotSteal(t *testing.T) {
	waf := newTestWafEngine()
	simulateLoadHostMaps(waf, model.Hosts{Code: "A", Host: "shared.example.com", Port: 80})
	simulateLoadHostMaps(waf, model.Hosts{Code: "B", Host: "other.example.com", Port: 80, BindMoreHost: "shared.example.com"})
	if lookupCode(waf, "shared.example.com", false) != "A" {
		t.Fatalf("主域名占用后 BindMoreHost 不得抢走，got %q", lookupCode(waf, "shared.example.com", false))
	}
}

func TestHostOverlap_AutoJumpDoesNotOverwriteOtherSite80(t *testing.T) {
	waf := newTestWafEngine()
	a := model.Hosts{Code: "A", Host: "shared.example.com", Port: 80}
	b := model.Hosts{Code: "B", Host: "shared.example.com", Port: 443, Ssl: 1, AutoJumpHTTPS: 1}
	simulateLoadHostMaps(waf, a)
	simulateLoadHostMaps(waf, b)
	if lookupCode(waf, "shared.example.com:80", false) != "A" {
		t.Fatalf(":80 应仍是 A，got %q", lookupCode(waf, "shared.example.com:80", false))
	}
	if lookupCode(waf, "shared.example.com:443", true) != "B" {
		t.Fatalf(":443 应是 B，got %q", lookupCode(waf, "shared.example.com:443", true))
	}
	waf.RemoveHost(b)
	if lookupCode(waf, "shared.example.com:80", false) != "A" {
		t.Fatal("删除 B 不得清掉 A 的 :80")
	}
}

func TestHostOverlap_RemoveBindMoreDoesNotWipeOwnerNoPort(t *testing.T) {
	waf := newTestWafEngine()
	a := model.Hosts{Code: "A", Host: "shared.example.com", Port: 80, UnrestrictedPort: 1}
	b := model.Hosts{Code: "B", Host: "other.example.com", Port: 8080, BindMoreHost: "shared.example.com"}
	simulateLoadHostMaps(waf, a)
	simulateLoadHostMaps(waf, b)
	waf.RemoveHost(b)
	if waf.rt().HostTargetNoPort["shared.example.com"] == "" {
		t.Fatal("删除 B 不得清掉 A 的宽松端口映射")
	}
	if lookupCode(waf, "shared.example.com", false) != "A" {
		t.Fatal("删除 B 后 A 应仍能按域名命中")
	}
}

func TestSSL_GetSSL_IDNAndCase(t *testing.T) {
	puny, err := idna.Lookup.ToASCII("例子.com")
	if err != nil {
		t.Fatal(err)
	}
	waf := newTestWafEngine()
	cert := new(tls.Certificate)
	waf.AllCertificate.Mux.Lock()
	waf.AllCertificate.Map[utils.CanonicalHost("例子.com")] = cert
	waf.AllCertificate.Mux.Unlock()
	if waf.AllCertificate.GetSSL(puny) == nil {
		t.Fatal("证书按中文入库后，Punycode SNI 应能取到")
	}
	if waf.AllCertificate.GetSSL("例子.com") == nil {
		t.Fatal("中文 SNI 也应取到")
	}

	waf2 := newTestWafEngine()
	waf2.AllCertificate.Mux.Lock()
	waf2.AllCertificate.Map[utils.CanonicalHost("Example.COM")] = cert
	waf2.AllCertificate.Mux.Unlock()
	if waf2.AllCertificate.GetSSL("example.com") == nil {
		t.Fatal("证书大小写应不敏感")
	}
}