package wafenginecore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/common/queue"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafbot"

	goahocorasick "github.com/samwafgo/ahocorasick"
)

const (
	notifyClassificationHostCode = "notify-classification-host"
	notifyClassificationIP       = "192.0.2.123"
	notifyClassificationPath     = "/notify-check"
)

type notifyClassificationQueues struct {
	messages *queue.Queue
	logs     *queue.Queue
	expected int
	received int
}

func newNotifyClassificationQueues(t *testing.T) *notifyClassificationQueues {
	t.Helper()
	oldCache, oldMessages, oldLogs := global.GCACHE_WAFCACHE, global.GQEQUE_MESSAGE_DB, global.GQEQUE_LOG_DB
	oldName, oldCode := global.GWAF_GLOBAL_HOST_NAME, global.GWAF_GLOBAL_HOST_CODE
	oldServer, oldLocation := global.GWAF_CUSTOM_SERVER_NAME, global.GIPLOCATION_MANAGER
	oldChain, oldSpider, oldOwasp := global.GCONFIG_RULE_CHAIN_MODE, global.GCONFIG_RECORD_SPIDER_DENY, global.GCONFIG_RECORD_ENABLE_OWASP
	oldQPS := atomic.LoadUint64(&global.GWAF_RUNTIME_QPS)
	oldTraffic := global.DrainTraffic()
	connectionLock.Lock()
	oldConnections, hadConnections := activeConnections[notifyClassificationHostCode]
	connectionLock.Unlock()
	qpsLock.Lock()
	oldSiteQPS, hadSiteQPS := siteQPS[notifyClassificationHostCode]
	qpsLock.Unlock()

	q := &notifyClassificationQueues{messages: queue.NewQueue(), logs: queue.NewQueue()}
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	global.GQEQUE_MESSAGE_DB, global.GQEQUE_LOG_DB = q.messages, q.logs
	global.GWAF_GLOBAL_HOST_NAME, global.GWAF_GLOBAL_HOST_CODE = "notify-global:0", "notify-global"
	global.GWAF_CUSTOM_SERVER_NAME, global.GIPLOCATION_MANAGER = "notify-test-server", nil
	global.GCONFIG_RULE_CHAIN_MODE, global.GCONFIG_RECORD_SPIDER_DENY, global.GCONFIG_RECORD_ENABLE_OWASP = 0, 1, 0

	t.Cleanup(func() {
		// Wait for scheduled notifications before restoring the queues.
		deadline := time.Now().Add(3 * time.Second)
		for q.received+q.messages.Size() < q.expected && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		if got := q.received + q.messages.Size(); got != q.expected {
			t.Errorf("notification total = %d, want %d", got, q.expected)
		}
		global.GCACHE_WAFCACHE, global.GQEQUE_MESSAGE_DB, global.GQEQUE_LOG_DB = oldCache, oldMessages, oldLogs
		global.GWAF_GLOBAL_HOST_NAME, global.GWAF_GLOBAL_HOST_CODE = oldName, oldCode
		global.GWAF_CUSTOM_SERVER_NAME, global.GIPLOCATION_MANAGER = oldServer, oldLocation
		global.GCONFIG_RULE_CHAIN_MODE, global.GCONFIG_RECORD_SPIDER_DENY, global.GCONFIG_RECORD_ENABLE_OWASP = oldChain, oldSpider, oldOwasp
		atomic.StoreUint64(&global.GWAF_RUNTIME_QPS, oldQPS)
		global.DrainTraffic()
		for _, traffic := range oldTraffic {
			global.AddTraffic(traffic.HostCode, traffic.Host, traffic.Day, traffic.HourTime, traffic.In, traffic.Out)
		}
		connectionLock.Lock()
		if hadConnections {
			activeConnections[notifyClassificationHostCode] = oldConnections
		} else {
			delete(activeConnections, notifyClassificationHostCode)
		}
		connectionLock.Unlock()
		qpsLock.Lock()
		if hadSiteQPS {
			siteQPS[notifyClassificationHostCode] = oldSiteQPS
		} else {
			delete(siteQPS, notifyClassificationHostCode)
		}
		qpsLock.Unlock()
	})
	return q
}

func (q *notifyClassificationQueues) noMessage(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(50 * time.Millisecond)
	for {
		if n := q.messages.Size(); n != 0 {
			t.Fatalf("unexpected extra notifications: %d", n)
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (q *notifyClassificationQueues) blockLog(t *testing.T, status int, rulePart string) *innerbean.WebLog {
	t.Helper()
	if n := q.logs.Size(); n != 1 {
		t.Fatalf("block log count = %d, want 1", n)
	}
	value, _ := q.logs.Dequeue()
	log, ok := value.(*innerbean.WebLog)
	if !ok {
		t.Fatalf("log type = %T", value)
	}
	if log.STATUS_CODE != status || log.ACTION != "阻止" || !strings.Contains(log.RULE, rulePart) {
		t.Fatalf("block log: status=%d action=%q rule=%q", log.STATUS_CODE, log.ACTION, log.RULE)
	}
	return log
}

func (q *notifyClassificationQueues) message(t *testing.T, log *innerbean.WebLog, attack bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for q.messages.Empty() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	value, ok := q.messages.Dequeue()
	if !ok {
		t.Fatal("notification did not arrive")
	}
	q.received++
	var base innerbean.BaseMessageInfo
	var domain, ip string
	if attack {
		message, ok := value.(innerbean.AttackInfoMessageInfo)
		if !ok {
			t.Fatalf("notification type = %T, want AttackInfoMessageInfo", value)
		}
		base, domain, ip = message.BaseMessageInfo, message.Domain, message.Ip
		if message.AttackType != log.RULE || message.Url != log.URL || message.OperaType != "攻击信息" {
			t.Fatalf("attack notification differs from log: %+v", message)
		}
		if _, err := time.ParseInLocation("2006-01-02 15:04:05", message.Time, time.Local); err != nil {
			t.Fatalf("notification time = %q: %v", message.Time, err)
		}
	} else {
		message, ok := value.(innerbean.RuleMessageInfo)
		if !ok {
			t.Fatalf("notification type = %T, want RuleMessageInfo", value)
		}
		base, domain, ip = message.BaseMessageInfo, message.Domain, message.Ip
		if message.RuleInfo != log.RULE || message.OperaType != "命中保护规则" {
			t.Fatalf("rule notification differs from log: %+v", message)
		}
	}
	ipMatches := ip == log.SRC_IP
	if !attack {
		ipMatches = strings.HasPrefix(ip, log.SRC_IP+" (")
	}
	if base.Server != "notify-test-server" || domain != log.HOST || !ipMatches {
		t.Fatalf("notification identity: server=%q domain=%q ip=%q", base.Server, domain, ip)
	}
	q.noMessage(t)
}

func newNotifyClassificationEngine(t *testing.T, defense model.HostsDefense) *WafEngine {
	t.Helper()
	defenseJSON, err := json.Marshal(defense)
	if err != nil {
		t.Fatal(err)
	}
	waf := &WafEngine{ServerOnline: wafenginmodel.NewSafeServerMap()}
	waf.InitRouting()
	waf.withWriteTable(func(rt *routingTable) {
		rt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: global.GWAF_GLOBAL_HOST_CODE, GUARD_STATUS: 1},
		}
		rt.HostCode[global.GWAF_GLOBAL_HOST_CODE] = global.GWAF_GLOBAL_HOST_NAME
		rt.HostTarget["notify.test:80"] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: notifyClassificationHostCode, Host: "notify.test", Port: 80,
				GUARD_STATUS: 1, IPSourceMode: "nic", DEFENSE_JSON: string(defenseJSON)},
			PathRules: []model.HostPathRule{{Path: notifyClassificationPath, MatchType: 2, TargetType: 3,
				RedirectURL: "/notify-passed", RedirectCode: http.StatusFound}},
			BlockingPage: map[string]model.BlockingPage{
				"403": {ResponseCode: "403", ResponseContent: "notify-blocked"},
			},
		}
		rt.HostCode[notifyClassificationHostCode] = "notify.test:80"
	})
	return waf
}

func notifyClassificationRequest(query, userAgent string) *http.Request {
	target := "http://notify.test" + notifyClassificationPath
	if query != "" {
		target += "?" + url.Values{"q": {query}}.Encode()
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = net.JoinHostPort(notifyClassificationIP, "12345")
	r.Header.Set("User-Agent", userAgent)
	return r
}

func assertNotifyClassificationPassed(t *testing.T, waf *WafEngine, r *http.Request, q *notifyClassificationQueues) {
	t.Helper()
	w := httptest.NewRecorder()
	waf.ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/notify-passed" {
		t.Fatalf("request did not finish checks: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if n := q.logs.Size(); n != 0 {
		t.Fatalf("redirect enqueued %d block logs", n)
	}
	q.noMessage(t)
}

func TestNotifyClassificationServeHTTP(t *testing.T) {
	q := newNotifyClassificationQueues(t)
	builtins := []struct {
		name, query, userAgent, rule string
		defense                      model.HostsDefense
	}{
		{name: "Bot", rule: "伪装Google爬虫", defense: model.HostsDefense{DEFENSE_BOT: 1}},
		{name: "SQL", query: "admin' or '1'='1", rule: "SQL注入", defense: model.HostsDefense{DEFENSE_SQLI: 1}},
		{name: "XSS", query: "<script>alert(1)</script>", rule: "XSS跨站注入", defense: model.HostsDefense{DEFENSE_XSS: 1}},
		{name: "Scan", userAgent: "sqlmap", rule: "扫描工具", defense: model.HostsDefense{DEFENSE_SCAN: 1}},
		{name: "RCE", query: "phpinfo()", rule: "RCE:", defense: model.HostsDefense{DEFENSE_RCE: 1}},
		{name: "Traversal", query: "../x", rule: "目录穿越漏洞", defense: model.HostsDefense{DEFENSE_DIR_TRAVERSAL: 1}},
		{name: "Sensitive", query: "notify-marker", rule: "敏感词检测：notify-marker", defense: model.HostsDefense{DEFENSE_SENSITIVE: 1}},
	}
	for _, tc := range builtins {
		for _, logOnly := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/log_only_%d", tc.name, logOnly), func(t *testing.T) {
				waf := newNotifyClassificationEngine(t, tc.defense)
				waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) { h.Host.LogOnlyMode = logOnly })
				if tc.name == "Bot" {
					// Cached identity keeps the request independent of DNS.
					global.GCACHE_WAFCACHE.Set(enums.CACHE_DNS_BOT_IP+notifyClassificationIP,
						wafbot.BotResult{IsBot: true, BotName: tc.rule})
				}
				if tc.name == "Sensitive" {
					sensitive := model.Sensitive{Content: "notify-marker", Action: "deny", CheckDirection: "in"}
					waf.Sensitive = []model.Sensitive{sensitive}
					waf.SensitiveDirectionMap = map[string]bool{"in": true}
					waf.SensitiveManager = new(goahocorasick.Machine)
					if err := waf.SensitiveManager.BuildByCustom([][]rune{[]rune(sensitive.Content)},
						map[string]interface{}{sensitive.Content: sensitive}); err != nil {
						t.Fatal(err)
					}
				}
				r := notifyClassificationRequest(tc.query, tc.userAgent)
				if logOnly == 1 {
					assertNotifyClassificationPassed(t, waf, r, q)
					return
				}
				q.expected++
				w := httptest.NewRecorder()
				waf.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden || w.Body.String() != "notify-blocked" {
					t.Fatalf("block response: status=%d body=%q", w.Code, w.Body.String())
				}
				log := q.blockLog(t, http.StatusForbidden, tc.rule)
				if log.URL != r.RequestURI || log.SRC_IP != notifyClassificationIP || log.HOST != "http://notify.test" {
					t.Fatalf("request log identity: url=%q ip=%q host=%q", log.URL, log.SRC_IP, log.HOST)
				}
				q.message(t, log, tc.name != "Sensitive")
			})
		}
	}

	for _, chain := range []int64{0, 1} {
		for _, title := range []string{"SQL 自定义规则", "XSS 自定义规则", "RCE 自定义规则"} {
			t.Run(fmt.Sprintf("custom/chain_%d/%s", chain, title), func(t *testing.T) {
				global.GCONFIG_RULE_CHAIN_MODE = chain
				waf := newNotifyClassificationEngine(t, model.HostsDefense{})
				rule := buildRuleHelper(t, fmt.Sprintf(`rule Rtest001 %q salience 10 {
    when MF.METHOD == "GET"
    then RF.Deny();
}`, title))
				waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) { h.Rule = rule })
				q.expected++
				w := httptest.NewRecorder()
				waf.ServeHTTP(w, notifyClassificationRequest("", ""))
				if w.Code != http.StatusForbidden {
					t.Fatalf("custom rule response = %d", w.Code)
				}
				q.message(t, q.blockLog(t, http.StatusForbidden, title), false)
			})
		}
	}

	for _, scope := range []string{notifyClassificationHostCode, global.GWAF_GLOBAL_HOST_CODE} {
		t.Run("IPBlacklist/"+scope, func(t *testing.T) {
			waf := newNotifyClassificationEngine(t, model.HostsDefense{})
			setBlockList(waf, scope, []model.IPBlockList{{Ip: notifyClassificationIP}})
			q.expected++
			w := httptest.NewRecorder()
			waf.ServeHTTP(w, notifyClassificationRequest("", ""))
			if w.Code != http.StatusForbidden {
				t.Fatalf("blacklist response = %d", w.Code)
			}
			q.message(t, q.blockLog(t, http.StatusForbidden, "IP黑名单"), false)
		})
	}

	t.Run("clean", func(t *testing.T) {
		assertNotifyClassificationPassed(t, newNotifyClassificationEngine(t, model.HostsDefense{}), notifyClassificationRequest("hello", ""), q)
	})
	for _, action := range []string{"Allow", "Log", "DenyLogOnly"} {
		t.Run("custom/"+action, func(t *testing.T) {
			global.GCONFIG_RULE_CHAIN_MODE = 1
			waf := newNotifyClassificationEngine(t, model.HostsDefense{DEFENSE_XSS: 1})
			ruleAction := action + "()"
			if action == "DenyLogOnly" {
				ruleAction = "Deny()"
			} else if action == "Allow" {
				ruleAction = `Allow("XSS")`
			}
			rule := buildRuleHelper(t, fmt.Sprintf(`rule Rtest001 "SQL XSS RCE 策略" salience 10 {
    when MF.METHOD == "GET"
    then RF.%s;
}`, ruleAction))
			waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
				h.Rule = rule
				if action == "DenyLogOnly" {
					h.Host.LogOnlyMode = 1
				}
			})
			query := "hello"
			if action == "Allow" {
				query = "<script>alert(1)</script>"
			}
			r := notifyClassificationRequest(query, "")
			host, _ := waf.GetHostByCode(notifyClassificationHostCode)
			result := waf.CheckRule(r, &innerbean.WebLog{METHOD: http.MethodGet}, nil, host, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME])
			if (action == "Allow" && !result.IsRuleAllow) || (action == "Log" && !result.IsLogOnly) || (action == "DenyLogOnly" && !result.IsBlock) {
				t.Fatalf("custom rule did not match requested action: %+v", result)
			}
			assertNotifyClassificationPassed(t, waf, r, q)
		})
	}
}

type notifyClassificationHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *notifyClassificationHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, nil, nil
}

func TestNotifyClassificationEchoExits(t *testing.T) {
	q := newNotifyClassificationQueues(t)
	for _, entry := range []string{"request", "response", "request444Fallback"} {
		for _, code := range []int{http.StatusForbidden, 444} {
			if entry == "request444Fallback" && code != 444 {
				continue
			}
			for _, attack := range []bool{false, true} {
				for _, isLog := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d/attack_%t/log_%t", entry, code, attack, isLog), func(t *testing.T) {
						host := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{
							"403": {ResponseCode: strconv.Itoa(code), ResponseContent: "notify-blocked"},
						}}
						globalHost := &wafenginmodel.HostSafe{}
						log := &innerbean.WebLog{HOST: "http://notify.test", URL: notifyClassificationPath,
							SRC_IP: notifyClassificationIP, REQ_UUID: "notify-echo", UNIX_ADD_TIME: time.Now().UnixMilli()}
						ruleName, attackType := "敏感词检测：notify-marker", "sensitive_word"
						var messageType []string
						if attack {
							ruleName, attackType = "SQL注入", "sql_injection"
							messageType = []string{model.MSG_TYPE_ATTACK_INFO}
						}
						if isLog {
							q.expected++
						}
						wantStatus := code
						if entry == "request444Fallback" {
							wantStatus = http.StatusForbidden
						}
						if entry == "response" {
							resp := newBackendResp(http.StatusOK, "200 OK", "text/plain", []byte("upstream"))
							EchoResponseErrorInfo(resp, log, ruleName, "blocked", host, globalHost, isLog, attackType, messageType...)
							body := readBody(t, resp)
							wantBody := "notify-blocked"
							if code == 444 {
								wantBody = ""
							}
							if resp.StatusCode != wantStatus || string(body) != wantBody || resp.ContentLength != int64(len(body)) || resp.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
								t.Fatalf("response exit: status=%d length=%d body=%q", resp.StatusCode, resp.ContentLength, body)
							}
						} else {
							recorder := httptest.NewRecorder()
							var writer http.ResponseWriter = recorder
							var peer net.Conn
							if entry == "request" && code == 444 {
								conn, other := net.Pipe()
								t.Cleanup(func() { conn.Close(); other.Close() })
								if err := other.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
									t.Fatal(err)
								}
								writer, peer = &notifyClassificationHijacker{ResponseRecorder: recorder, conn: conn}, other
							}
							got := EchoErrorInfo(writer, notifyClassificationRequest("", ""), log, ruleName, "blocked", host, globalHost, isLog, attackType, messageType...)
							if got != wantStatus {
								t.Fatalf("request exit status = %d, want %d", got, wantStatus)
							}
							if peer != nil {
								if n, err := peer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
									t.Fatalf("444 connection: bytes=%d err=%v", n, err)
								}
								if recorder.Body.Len() != 0 {
									t.Fatal("444 wrote a response body")
								}
							} else if recorder.Code != wantStatus || recorder.Body.String() != "notify-blocked" {
								t.Fatalf("request exit: status=%d body=%q", recorder.Code, recorder.Body.String())
							}
						}
						if isLog {
							q.message(t, q.blockLog(t, wantStatus, ruleName), attack)
						} else {
							if n := q.logs.Size(); n != 0 {
								t.Fatalf("isLog=false enqueued %d logs", n)
							}
							q.noMessage(t)
						}
					})
				}
			}
		}
	}
}
