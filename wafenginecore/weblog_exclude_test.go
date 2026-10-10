package wafenginecore

import (
	"SamWaf/common/queue"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/accessgate"
	"SamWaf/wafenginecore/ipset"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParseIPLogExcludeLines(t *testing.T) {
	patterns, codes := parseIPLogExcludeLines(`
# 办公出口
203.0.113.7, 198.51.100.0/24
10.0.0.1-10.0.0.9
group:office-net
Group:Probe-Net
group:office-net
`)
	if !reflect.DeepEqual(patterns, []string{"203.0.113.7", "198.51.100.0/24", "10.0.0.1-10.0.0.9"}) {
		t.Errorf("patterns = %v", patterns)
	}
	// 组短码去重保序；group: 前缀大小写不敏感，组短码本身保持原样
	if !reflect.DeepEqual(codes, []string{"office-net", "Probe-Net"}) {
		t.Errorf("codes = %v", codes)
	}

	patterns, codes = parseIPLogExcludeLines("  \n# 只有注释\n")
	if patterns != nil || codes != nil {
		t.Errorf("空清单应得到 nil,nil，实际 %v %v", patterns, codes)
	}
}

func TestBuildIPLogExcludeIndexMatch(t *testing.T) {
	idx := BuildIPLogExcludeIndex("203.0.113.7,198.51.100.0/24,10.*.*.*,坏行!,group:不会被收进索引")
	if idx == nil {
		t.Fatal("非空清单应返回索引")
	}
	for ip, want := range map[string]bool{
		"203.0.113.7":   true,
		"198.51.100.9":  true,
		"10.1.2.3":      true,
		"203.0.113.8":   false,
		"192.0.2.1":     false,
	} {
		if got := idx.ContainsStr(ip); got != want {
			t.Errorf("ContainsStr(%s) = %v, want %v", ip, got, want)
		}
	}
	if BuildIPLogExcludeIndex("") != nil || BuildIPLogExcludeIndex("# 注释\n") != nil {
		t.Error("空清单应返回 nil 索引")
	}
}

// TestShouldRecordWebLogIPExclude D13 语义：排除 IP 只静音正常请求，安全事件照记。
func TestShouldRecordWebLogIPExclude(t *testing.T) {
	origin := global.GWAF_RUNTIME_RECORD_LOG_TYPE
	defer func() { global.GWAF_RUNTIME_RECORD_LOG_TYPE = origin }()
	SetGlobalIPLogExclude("")
	defer SetGlobalIPLogExclude("")

	mkHost := func(raw string) *wafenginmodel.HostSafe {
		return &wafenginmodel.HostSafe{
			Host:                   model.Hosts{EXCLUDE_IP_LOG: raw},
			IPLogExcludeIndex:      BuildIPLogExcludeIndex(raw),
			IPLogExcludeGroupCodes: ExtractIPLogExcludeGroupCodes(raw),
		}
	}
	cases := []struct {
		name    string
		logType string
		weblog  *innerbean.WebLog
		hostRaw string
		want    bool
	}{
		{"all_排除IP的正常请求不记", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "203.0.113.7"},
			"203.0.113.7", false},
		{"all_排除IP的安全事件照记", "all",
			&innerbean.WebLog{ACTION: "阻止", RULE: "SQL注入", URL: "/a", SRC_IP: "203.0.113.7"},
			"203.0.113.7", true},
		{"abnormal_排除IP的安全事件照记", "abnormal",
			&innerbean.WebLog{ACTION: "阻止", RULE: "SQL注入", URL: "/a", SRC_IP: "203.0.113.7"},
			"203.0.113.7", true},
		{"all_未排除IP不受影响", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "198.51.100.1"},
			"203.0.113.7", true},
		{"all_排除网段命中", "all",
			&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "10.0.0.9"},
			"10.0.0.0/8", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global.GWAF_RUNTIME_RECORD_LOG_TYPE = tc.logType
			if got := shouldRecordWebLog(tc.weblog, mkHost(tc.hostRaw)); got != tc.want {
				t.Errorf("期望 %v 实际 %v", tc.want, got)
			}
		})
	}

	t.Run("all_排除清单里的IP组命中", func(t *testing.T) {
		global.GWAF_RUNTIME_RECORD_LOG_TYPE = "all"
		ipset.UpsertGroupMatcher("m6-test-grp", "测试组", ipset.BuildMatchSet([]string{"192.0.2.66"}))
		defer ipset.RemoveGroupMatcher("m6-test-grp")
		hostSafe := mkHost("group:m6-test-grp")
		if got := shouldRecordWebLog(&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "192.0.2.66"}, hostSafe); got {
			t.Error("组内 IP 的正常请求应被排除")
		}
	})

	t.Run("all_全局排除清单命中", func(t *testing.T) {
		global.GWAF_RUNTIME_RECORD_LOG_TYPE = "all"
		SetGlobalIPLogExclude("203.0.113.99")
		defer SetGlobalIPLogExclude("")
		hostSafe := mkHost("")
		if got := shouldRecordWebLog(&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "203.0.113.99"}, hostSafe); got {
			t.Error("全局排除命中，正常请求不应记录")
		}
		if got := shouldRecordWebLog(&innerbean.WebLog{ACTION: "放行", URL: "/a", SRC_IP: "203.0.113.100"}, hostSafe); !got {
			t.Error("未命中全局排除，照常记录")
		}
	})
}

// TestAccessPingNotEnqueued H2：自带 /<前缀>/ping 探测点由访问认证网关直接代答 204，
// 整条路径不入日志队列。该行为此前无测试钉住（实施计划 §5.8 曾误以为它会产生日志）。
func TestAccessPingNotEnqueued(t *testing.T) {
	accessgate.SetConfig(&accessgate.Config{PathPrefix: "/samwaf_access"})
	defer accessgate.SetConfig(nil)

	origin := global.GQEQUE_LOG_DB
	global.GQEQUE_LOG_DB = queue.NewQueue()
	defer func() { global.GQEQUE_LOG_DB = origin }()

	waf := &WafEngine{}
	req := httptest.NewRequest(http.MethodGet, "http://www.example.com/samwaf_access/ping", nil)
	rec := httptest.NewRecorder()
	hostSafe := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "m6-test"}}
	weblog := &innerbean.WebLog{SRC_IP: "192.0.2.10", URL: "/samwaf_access/ping"}

	waf.handleAccessRequest(rec, req, hostSafe, weblog, accessgate.Get(), model.HostAccessConfig{}, "192.0.2.10")

	if rec.Code != http.StatusNoContent {
		t.Errorf("ping 应回 204，实际 %d", rec.Code)
	}
	if global.GQEQUE_LOG_DB.Size() != 0 {
		t.Error("ping 请求不应进日志队列")
	}
}
