package wafenginecore

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/common/queue"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/ipset"
)

type ipAllowBlockAllCase struct {
	name        string
	prefix      string
	member      string
	nonmember   string
	blockHost   string
	allowHost   string
	group       bool
	globalGuard int
}

func ipAllowBlockAllCases() []ipAllowBlockAllCase {
	var cases []ipAllowBlockAllCase
	for _, family := range []struct {
		name, prefix, member, nonmember string
	}{
		{"IPv4", "0.0.0.0/0", "192.0.2.10", "192.0.2.11"},
		{"IPv6", "::/0", "2001:db8::10", "2001:db8::11"},
	} {
		for _, blockHost := range []string{"codeA", "codeGlobal"} {
			for _, allowHost := range []string{"codeA", "codeGlobal"} {
				for _, group := range []bool{false, true} {
					for _, guard := range []int{0, 1} {
						kind := "single_ip"
						if group {
							kind = "group"
						}
						cases = append(cases, ipAllowBlockAllCase{
							name: fmt.Sprintf("%s/block_%s/allow_%s/%s/global_guard_%d",
								family.name, blockHost, allowHost, kind, guard),
							prefix: family.prefix, member: family.member, nonmember: family.nonmember,
							blockHost: blockHost, allowHost: allowHost, group: group, globalGuard: guard,
						})
					}
				}
			}
		}
	}
	return cases
}

func (tc ipAllowBlockAllCase) setAllow(waf *WafEngine) {
	entry := model.IPAllowList{Ip: tc.member}
	if tc.group {
		const groupCode = "allow-block-all-test"
		ipset.UpsertGroupMatcher(groupCode, "", ipset.BuildMatchSet([]string{tc.member}))
		entry = model.IPAllowList{IpType: model.IPEntryTypeGroup, GroupCode: groupCode}
	}
	setAllowList(waf, tc.allowHost, []model.IPAllowList{entry})
}

func TestIPAllowBlockAll_Matchers(t *testing.T) {
	for _, tc := range ipAllowBlockAllCases() {
		t.Run(tc.name, func(t *testing.T) {
			waf := newIPGroupTestEngine(t, tc.globalGuard)
			setBlockList(waf, tc.blockHost, []model.IPBlockList{{Ip: tc.prefix}})
			wantBlock := tc.blockHost == "codeA" || tc.globalGuard == 1
			for _, ip := range []string{tc.member, tc.nonmember} {
				if got := denyBlocked(t, waf, "codeA", ip); got != wantBlock {
					t.Fatalf("before whitelist: deny(%s) = %v, want %v", ip, got, wantBlock)
				}
				if allowJumped(t, waf, "codeA", ip) {
					t.Fatalf("empty whitelist matched %s", ip)
				}
			}

			tc.setAllow(waf)
			wantAllow := tc.allowHost == "codeA" || tc.globalGuard == 1
			if got := allowJumped(t, waf, "codeA", tc.member); got != wantAllow {
				t.Errorf("member whitelist match = %v, want %v", got, wantAllow)
			}
			if allowJumped(t, waf, "codeA", tc.nonmember) {
				t.Error("whitelist matched an address outside its single IP or group")
			}
			for _, ip := range []string{tc.member, tc.nonmember} {
				if got := denyBlocked(t, waf, "codeA", ip); got != wantBlock {
					t.Errorf("after whitelist: deny(%s) = %v, want %v", ip, got, wantBlock)
				}
			}

			if got := allowJumped(t, waf, "codeB", tc.member); got != (tc.allowHost == "codeGlobal" && tc.globalGuard == 1) {
				t.Errorf("other site whitelist match = %v", got)
			}
			if got := denyBlocked(t, waf, "codeB", tc.member); got != (tc.blockHost == "codeGlobal" && tc.globalGuard == 1) {
				t.Errorf("other site blacklist match = %v", got)
			}
		})
	}
}

// ServeHTTP itself determines precedence; the redirect marks completed request checks without an upstream.
func TestIPAllowBlockAll_ServeHTTP(t *testing.T) {
	oldCache, oldLogQ, oldMsgQ := global.GCACHE_WAFCACHE, global.GQEQUE_LOG_DB, global.GQEQUE_MESSAGE_DB
	oldGlobalCode := global.GWAF_GLOBAL_HOST_CODE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	global.GQEQUE_LOG_DB = queue.NewQueue()
	global.GQEQUE_MESSAGE_DB = queue.NewQueue()
	global.GWAF_GLOBAL_HOST_CODE = "codeGlobal"
	messageQueue := global.GQEQUE_MESSAGE_DB
	blockedRequests := 0
	t.Cleanup(func() {
		// EchoErrorInfo queues notifications asynchronously; wait before restoring its global queue.
		deadline := time.Now().Add(2 * time.Second)
		for messageQueue.Size() < blockedRequests && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := messageQueue.Size(); got != blockedRequests {
			t.Errorf("block notifications = %d, want %d", got, blockedRequests)
		}
		global.GCACHE_WAFCACHE, global.GQEQUE_LOG_DB, global.GQEQUE_MESSAGE_DB = oldCache, oldLogQ, oldMsgQ
		global.GWAF_GLOBAL_HOST_CODE = oldGlobalCode
	})

	for _, tc := range ipAllowBlockAllCases() {
		t.Run(tc.name, func(t *testing.T) {
			waf := newIPGroupTestEngine(t, tc.globalGuard)
			waf.ServerOnline = wafenginmodel.NewSafeServerMap()
			waf.UpdateHost("codeA", func(h *wafenginmodel.HostSafe) {
				h.Host.Port = 80
				h.Host.IPSourceMode = "nic"
				h.PathRules = []model.HostPathRule{{
					Path: "/ip-list-test", MatchType: 2, TargetType: 3,
					RedirectURL: "/ip-list-passed", RedirectCode: http.StatusFound,
				}}
				h.BlockingPage = map[string]model.BlockingPage{
					"403": {ResponseCode: "403", ResponseContent: "ip-list-blocked"},
				}
			})
			setBlockList(waf, tc.blockHost, []model.IPBlockList{{Ip: tc.prefix}})

			request := func(ip string, wantStatus int) {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "http://a.com/ip-list-test", nil)
				req.RemoteAddr = net.JoinHostPort(ip, "12345")
				rec := httptest.NewRecorder()
				waf.ServeHTTP(rec, req)
				if rec.Code == http.StatusForbidden {
					blockedRequests++
				}
				if rec.Code != wantStatus {
					t.Fatalf("ServeHTTP(%s) = %d, want %d; body=%q", ip, rec.Code, wantStatus, rec.Body.String())
				}
				if wantStatus == http.StatusFound {
					if got := rec.Header().Get("Location"); got != "/ip-list-passed" {
						t.Fatalf("redirect location = %q", got)
					}
					return
				}
				if got := rec.Body.String(); got != "ip-list-blocked" {
					t.Fatalf("block body = %q", got)
				}
				v, ok := global.GQEQUE_LOG_DB.Dequeue()
				if !ok {
					t.Fatal("blocked request did not enqueue a log")
				}
				log, ok := v.(*innerbean.WebLog)
				if !ok {
					t.Fatalf("block log type = %T", v)
				}
				wantRule := "IP黑名单"
				if tc.blockHost == "codeGlobal" {
					wantRule = "【全局】IP黑名单"
				}
				if log.RULE != wantRule || log.SRC_IP != ip || log.STATUS_CODE != http.StatusForbidden {
					t.Fatalf("unexpected block log: rule=%q ip=%q status=%d", log.RULE, log.SRC_IP, log.STATUS_CODE)
				}
			}

			wantBlock := tc.blockHost == "codeA" || tc.globalGuard == 1
			baselineStatus := http.StatusFound
			if wantBlock {
				baselineStatus = http.StatusForbidden
			}
			request(tc.member, baselineStatus)
			tc.setAllow(waf)
			memberStatus := http.StatusFound
			if wantBlock && tc.allowHost == "codeGlobal" && tc.globalGuard == 0 {
				memberStatus = http.StatusForbidden
			}
			request(tc.member, memberStatus)
			request(tc.nonmember, baselineStatus)
		})
	}
}
