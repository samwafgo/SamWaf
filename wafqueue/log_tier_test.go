package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
	"testing"
)

// 分层写入的纯逻辑用例。每个用例前重置档位与蓄水池，互不影响。
func resetTier(mode string) func() {
	savedMode := global.GDATA_ACCESS_LOG_MODE
	savedSampler := negSampler
	global.GDATA_ACCESS_LOG_MODE = mode
	negSampler = &sampleReservoir{buckets: map[string]*sampleBucket{}}
	return func() {
		global.GDATA_ACCESS_LOG_MODE = savedMode
		negSampler = savedSampler
	}
}

func mkLog(uuid, ip string) *innerbean.WebLog {
	return &innerbean.WebLog{
		REQ_UUID: uuid, HOST_CODE: "h1", SRC_IP: ip, URL: "/login",
		ACTION: "放行", CREATE_TIME: "2026-09-18 10:00:00", UNIX_ADD_TIME: 1, Day: 20260918,
		HEADER: "User-Agent: curl", BODY: "a=1", RES_BODY: "ok",
	}
}

// 安全事件：窄行双写（security_event + access_log），报文进 event_payload(kind=event)，HEADER 随报文走
func TestTier_EventWritesAllLayers(t *testing.T) {
	defer resetTier("off")() // off 档也不影响事件
	lg := mkLog("e1", "1.2.3.4")
	lg.ACTION = "阻止"
	lg.RULE = "SQLi:Union"

	events, accesses, payloads := tierForStore([]*innerbean.WebLog{lg})

	if len(events) != 1 || len(accesses) != 1 || len(payloads) != 1 {
		t.Fatalf("事件应进三张表，实际 %d/%d/%d", len(events), len(accesses), len(payloads))
	}
	if payloads[0].Kind != PayloadKindEvent {
		t.Fatalf("事件报文 kind 应为 event，实际 %q", payloads[0].Kind)
	}
	if payloads[0].HEADER != "User-Agent: curl" {
		t.Fatal("HEADER 随窄行拆分搬进报文表，不能丢")
	}
	if events[0].PayloadHash == "" {
		t.Fatal("事件必须带手法指纹")
	}
	if events[0].ActorKey != "ip:1.2.3.4" || events[0].PathNorm != "/login" {
		t.Fatalf("分析键没算好: %+v", events[0].LogNarrow)
	}
}

// db 档：正常请求窄行全量进 access_log；报文不进本批——被蓄水池采中的攒在池里定期刷库（D2）
func TestTier_DBModeNormalNoPayload(t *testing.T) {
	defer resetTier("db")()
	events, accesses, payloads := tierForStore([]*innerbean.WebLog{mkLog("n1", "1.2.3.4")})
	if len(events) != 0 || len(accesses) != 1 || len(payloads) != 0 {
		t.Fatalf("db 档正常请求应只有窄行，实际 %d/%d/%d", len(events), len(accesses), len(payloads))
	}
	// 第一条正常请求必被蓄水池采中
	if len(negSampler.snapshot()) != 1 {
		t.Fatal("正常请求应进蓄水池")
	}
}

// sample 档：采中的正常请求有窄行；超过蓄水池上限后，被替换挤出的也写了窄行（报文以池为准，宁多勿缺）
func TestTier_SampleMode(t *testing.T) {
	defer resetTier("sample")()
	logs := make([]*innerbean.WebLog, 0, sampleNegPerSiteDay+100)
	for i := 0; i < sampleNegPerSiteDay+100; i++ {
		logs = append(logs, mkLog("nx"+itoa(i), "1.2.3.4"))
	}
	events, accesses, payloads := tierForStore(logs)
	if len(events) != 0 || len(payloads) != 0 {
		t.Fatal("全是正常请求不该有事件与事件报文")
	}
	if len(accesses) < sampleNegPerSiteDay || len(accesses) > len(logs) {
		t.Fatalf("sample 档窄行数应在蓄水池上限与总量之间，实际 %d", len(accesses))
	}
	if got := len(negSampler.snapshot()); got != sampleNegPerSiteDay {
		t.Fatalf("蓄水池应恒为 %d 条，实际 %d", sampleNegPerSiteDay, got)
	}
}

// off 档：正常请求什么都不留，只留安全事件
func TestTier_OffModeDropsNormal(t *testing.T) {
	defer resetTier("off")()
	events, accesses, payloads := tierForStore([]*innerbean.WebLog{mkLog("n9", "1.2.3.4")})
	if len(events) != 0 || len(accesses) != 0 || len(payloads) != 0 {
		t.Fatalf("off 档正常请求应三层都不留，实际 %d/%d/%d", len(events), len(accesses), len(payloads))
	}
}

// 命中了规则但没拦（仅记录/自定义规则放行）也算事件——判定与引擎 abnormal 分支同一条规则
func TestTier_LogOnlyAndRulePassAreEvents(t *testing.T) {
	defer resetTier("off")()
	a := mkLog("lo1", "1.2.3.4")
	a.LogOnlyMode = 1
	b := mkLog("lo2", "1.2.3.4")
	b.RULE = "自定义规则放行"
	events, accesses, _ := tierForStore([]*innerbean.WebLog{a, b})
	if len(events) != 2 || len(accesses) != 2 {
		t.Fatalf("仅记录与带规则的放行都算事件，实际 %d/%d", len(events), len(accesses))
	}
}

// url 超 2KB 截断并置 Truncated；报文列的 64KB 截断只标在报文行上
func TestTier_URLTruncation(t *testing.T) {
	defer resetTier("db")()
	lg := mkLog("u1", "1.2.3.4")
	lg.URL = "/p/" + strings.Repeat("x", narrowURLMaxBytes)
	lg.ACTION = "阻止"

	events, accesses, _ := tierForStore([]*innerbean.WebLog{lg})
	if len(events[0].URL) > narrowURLMaxBytes || events[0].Truncated != 1 {
		t.Fatal("事件窄行 url 应截断到 2KB 并置 Truncated")
	}
	if accesses[0].Truncated != 1 {
		t.Fatal("access_log 窄行同样截断")
	}
	if len(lg.URL) <= narrowURLMaxBytes {
		t.Fatal("原对象不能被改（Kafka 出口要原文）")
	}
}

// 没有 req_uuid 的日志补一个再写——三张表都以它寻址，空主键会让整批互相覆盖
func TestTier_FillsMissingUUID(t *testing.T) {
	defer resetTier("db")()
	lg := mkLog("", "1.2.3.4")
	events, accesses, _ := tierForStore([]*innerbean.WebLog{lg})
	if lg.REQ_UUID == "" {
		t.Fatal("缺 req_uuid 应就地补上")
	}
	if len(accesses) != 1 || accesses[0].ReqUUID != lg.REQ_UUID {
		t.Fatal("窄行必须带着补上的 req_uuid")
	}
	_ = events
}

// 同一 req_uuid 一批来两条（分阶段入队），三张表都取后到的那条
func TestTier_DedupByUUID(t *testing.T) {
	defer resetTier("db")()
	first := mkLog("dup1", "1.2.3.4")
	first.ACTION = "阻止"
	second := mkLog("dup1", "1.2.3.4")
	second.ACTION = "阻止"
	second.RES_BODY = "done"

	events, accesses, payloads := tierForStore([]*innerbean.WebLog{first, second})
	if len(events) != 1 || len(accesses) != 1 || len(payloads) != 1 {
		t.Fatalf("三张表都应去重成 1 条，实际 %d/%d/%d", len(events), len(accesses), len(payloads))
	}
	if payloads[0].RES_BODY != "done" {
		t.Fatal("应保留后到的那条（信息更全）")
	}
}

// 原对象的报文必须原样留给 Kafka 出口与统计
func TestTier_KeepsOriginalIntact(t *testing.T) {
	defer resetTier("db")()
	big := strings.Repeat("b", payloadMaxBytes+1000)
	lg := mkLog("k1", "1.2.3.4")
	lg.ACTION = "阻止"
	lg.BODY = big

	tierForStore([]*innerbean.WebLog{lg})
	if len(lg.BODY) != len(big) || lg.Truncated != 0 {
		t.Fatal("原对象被改动了，Kafka 出口会拿到半截报文")
	}
}

// nil 条目跳过，不能带崩整批
func TestTier_SkipsNil(t *testing.T) {
	defer resetTier("db")()
	events, accesses, payloads := tierForStore([]*innerbean.WebLog{nil, mkLog("z1", "1.2.3.4")})
	if len(accesses) != 1 {
		t.Fatalf("nil 应被跳过，实际 %d/%d/%d", len(events), len(accesses), len(payloads))
	}
}

// 观察名单（C7）：名单内 IP 的正常请求任意档位都写窄行 + kind=watch 报文，且不再进采样池；
// 事件不受名单影响（报文已是 kind=event，一个 req_uuid 只有一条报文行）
func TestTier_WatchedIPFullCapture(t *testing.T) {
	defer resetTier("off")() // off 档也不影响观察名单
	savedHas := ipWatchHas
	ipWatchHas = func(ip string) bool { return ip == "9.9.9.9" }
	defer func() { ipWatchHas = savedHas }()

	normal := mkLog("w1", "9.9.9.9")
	event := mkLog("w2", "9.9.9.9")
	event.RULE = "SQLi"
	other := mkLog("w3", "1.2.3.4")

	events, accesses, payloads := tierForStore([]*innerbean.WebLog{normal, event, other})

	if len(events) != 1 || len(accesses) != 2 || len(payloads) != 2 {
		t.Fatalf("名单内正常+事件应各有窄行与报文，名单外 off 档不留，实际 %d/%d/%d",
			len(events), len(accesses), len(payloads))
	}
	kinds := map[string]string{}
	for _, p := range payloads {
		kinds[p.ReqUUID] = p.Kind
	}
	if kinds["w1"] != PayloadKindWatch || kinds["w2"] != PayloadKindEvent {
		t.Fatalf("报文 kind 不对: %v", kinds)
	}
	if len(negSampler.snapshot()) != 0 {
		t.Fatal("名单内的请求不重复进采样池")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
