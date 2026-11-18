package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestHTTPSRedirectBoundDomains(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "core.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(
		&model.Rules{}, &model.AntiCC{}, &model.AntiCCRule{}, &model.IPAllowList{}, &model.URLAllowList{},
		&model.IPBlockList{}, &model.URLBlockList{}, &model.LDPUrl{}, &model.LoadBalance{}, &model.HttpAuthBase{},
		&model.BlockingPage{}, &model.CacheRule{}, &model.TamperRule{}, &model.HostPathRule{},
	); err != nil {
		t.Fatal(err)
	}
	oldDB := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = oldDB })

	for _, tc := range []struct {
		name         string
		port         int
		listenJSON   string
		unrestricted int
		explicitHTTP bool
		wantPort     string
		incomingPort string
	}{
		{name: "legacy implicit HTTP", port: 443},
		{name: "explicit HTTPS with implicit HTTP", port: 8443, listenJSON: `[{"port":8443,"proto":"https"}]`, wantPort: ":8443"},
		{name: "explicit HTTP", port: 443, listenJSON: `[{"port":443,"proto":"https"},{"port":80,"proto":"http"}]`, explicitHTTP: true},
		{name: "HTTP primary with HTTPS secondary", port: 80, listenJSON: `[{"port":80,"proto":"http"},{"port":8443,"proto":"https"}]`, explicitHTTP: true, wantPort: ":8443"},
		{name: "explicit cleartext on port 443", port: 443, listenJSON: `[{"port":443,"proto":"http"},{"port":8443,"proto":"https"}]`, wantPort: ":8443", incomingPort: ":443"},
		{name: "unrestricted source port", port: 443, unrestricted: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := &WafEngine{ServerOnline: wafenginmodel.NewSafeServerMap()}
			waf.InitRouting()
			site := model.Hosts{
				Code: "https-site", Host: "main.test", Port: tc.port, Ssl: 1,
				AutoJumpHTTPS: 1, PortListensJSON: tc.listenJSON,
				UnrestrictedPort: tc.unrestricted, IPSourceMode: "nic",
			}
			waf.LoadHost(site)
			if match := resolveRequestHost(waf.rt(), "www.main.test", false, false); match.Found {
				t.Fatalf("alias matched before it was added: %+v", match)
			}
			site.BindMoreHost = "  www.main.test\r\n\r\n*.alias.test  "
			waf.LoadHost(site)

			const uri = "/docs/a%2Fb?q=a%2Bb"
			for _, domain := range []string{"main.test", "www.main.test", "shop.alias.test"} {
				visitorURL := "http://" + domain + tc.incomingPort + uri
				rec := httptest.NewRecorder()
				waf.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, visitorURL, nil))
				want := "https://" + domain + tc.wantPort + uri
				if got := rec.Header().Get("Location"); rec.Code != int(global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE) || got != want {
					t.Errorf("%s: HTTP %d, Location %q, want redirect to %q", domain, rec.Code, got, want)
				}
				snapshot, err := waf.DiagnosticSnapshot(site.Code, visitorURL, http.MethodGet, nil)
				if err != nil || snapshot.MatchCode != site.Code || snapshot.Mode != "https_redirect" {
					t.Errorf("%s: diagnostic match=%q mode=%q, err=%v", domain, snapshot.MatchCode, snapshot.Mode, err)
				}
			}

			for _, visitorURL := range []string{
				"http://unrelated.test/docs",
				"http://www.main.test" + global.GSSL_HTTP_CHANGLE_PATH + "test-token",
				"https://www.main.test" + tc.wantPort + "/docs",
			} {
				snapshot, err := waf.DiagnosticSnapshot(site.Code, visitorURL, http.MethodGet, nil)
				if err != nil || snapshot.Mode == "https_redirect" {
					t.Errorf("%s: diagnostic mode=%q, err=%v", visitorURL, snapshot.Mode, err)
				}
			}

			setupChallenge(t, site.Code)
			challenge := httptest.NewRecorder()
			waf.ServeHTTP(challenge, httptest.NewRequest(http.MethodGet,
				"http://www.main.test"+tc.incomingPort+global.GSSL_HTTP_CHANGLE_PATH+testChallengeToken, nil))
			if challenge.Code != http.StatusOK || challenge.Body.String() != testKeyAuth {
				t.Errorf("HTTP-01 for alias returned %d, want HTTP 200 and the registered response", challenge.Code)
			}

			site.AutoJumpHTTPS = 0
			waf.LoadHost(site)
			snapshot, err := waf.DiagnosticSnapshot(site.Code, "http://www.main.test/docs", http.MethodGet, nil)
			if err != nil || snapshot.Mode == "https_redirect" {
				t.Errorf("disabled redirect: diagnostic mode=%q, err=%v", snapshot.Mode, err)
			}
			if _, ok := waf.rt().HostTargetMoreDomain["www.main.test:80"]; ok != tc.explicitHTTP {
				t.Errorf("explicit alias route after disabling redirect: present=%v, want %v", ok, tc.explicitHTTP)
			}
			if _, ok := waf.rt().HostTargetRedirectAlias["www.main.test:80"]; ok {
				t.Error("implicit alias route remains after disabling redirect")
			}
		})
	}

	t.Run("configured HTTP site takes precedence", func(t *testing.T) {
		waf := &WafEngine{ServerOnline: wafenginmodel.NewSafeServerMap()}
		waf.InitRouting()
		const alias = "shared.test"
		httpSite := model.Hosts{Code: "explicit-http", Host: "http.test", Port: 80, BindMoreHost: alias}
		httpsSite := model.Hosts{Code: "redirect-https", Host: "https.test", Port: 443, Ssl: 1, AutoJumpHTTPS: 1, BindMoreHost: alias}
		waf.LoadHost(httpSite)
		waf.LoadHost(httpsSite)
		assertOwner := func(code string) {
			t.Helper()
			if match := resolveRequestHost(waf.rt(), alias, false, false); !match.Found || match.Code != code {
				t.Errorf("route for %s = %+v, want %s", alias, match, code)
			}
		}
		assertOwner(httpSite.Code)
		httpSite.BindMoreHost = ""
		waf.LoadHost(httpSite)
		assertOwner(httpsSite.Code)
		waf.RemoveHost(httpsSite)
		if match := resolveRequestHost(waf.rt(), alias, false, false); match.Found {
			t.Errorf("removed alias still matched: %+v", match)
		}
	})

	t.Run("sites sharing main and bound domains", func(t *testing.T) {
		waf := &WafEngine{ServerOnline: wafenginmodel.NewSafeServerMap()}
		waf.InitRouting()
		first := model.Hosts{Code: "a-site", Host: "main.test", Port: 443, Ssl: 1, AutoJumpHTTPS: 1, BindMoreHost: "shared.test", IPSourceMode: "nic"}
		second := first
		second.Code, second.Port = "b-site", 8443
		assertRedirect := func(want string) {
			t.Helper()
			rec := httptest.NewRecorder()
			waf.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://shared.test/docs", nil))
			if got := rec.Header().Get("Location"); rec.Code != int(global.GCONFIG_RECORD_REDIRECT_HTTPS_CODE) || got != want {
				t.Errorf("HTTP %d, Location %q, want %q", rec.Code, got, want)
			}
		}
		waf.LoadHost(first)
		waf.LoadHost(second)
		assertRedirect("https://shared.test/docs")
		waf.LoadHost(first)
		assertRedirect("https://shared.test/docs")
		waf.RemoveHost(first)
		assertRedirect("https://shared.test:8443/docs")
	})
}
