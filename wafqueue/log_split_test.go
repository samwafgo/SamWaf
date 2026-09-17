package wafqueue

import (
	"SamWaf/innerbean"
	"strings"
	"testing"
)

// 报文搬进 event_payload 行，web_logs 行只剩窄列
func TestSplitForStore_MovesPayload(t *testing.T) {
	origin := &innerbean.WebLog{
		REQ_UUID:  "uuid-1",
		HOST_CODE: "host-1",
		HEADER:    "User-Agent: curl",
		BODY:      "a=1",
		RES_BODY:  "ok",
		POST_FORM: "a=1",
		COOKIES:   "sid=x",
		ResHeader: "Content-Type: text/html",
		URL:       "/login",
	}

	narrow, payloads := splitForStore([]*innerbean.WebLog{origin})

	if len(narrow) != 1 || len(payloads) != 1 {
		t.Fatalf("应拆成 1 窄行 + 1 报文行，实际 %d/%d", len(narrow), len(payloads))
	}
	n := narrow[0]
	if n.BODY != "" || n.RES_BODY != "" || n.POST_FORM != "" ||
		n.COOKIES != "" || n.ResHeader != "" {
		t.Fatal("窄行的报文列没清干净")
	}
	if n.URL != "/login" {
		t.Fatal("非报文列不该被动")
	}
	// HEADER 本次不搬：访问日志页把它当独立列显示还带 LIKE 筛选
	if n.HEADER != "User-Agent: curl" {
		t.Fatal("HEADER 必须留在窄行上")
	}
	p := payloads[0]
	if p.ReqUUID != "uuid-1" || p.HostCode != "host-1" || p.Kind != PayloadKindEvent {
		t.Fatalf("报文行归属字段不对: %+v", p)
	}
	if p.BODY != "a=1" || p.RES_BODY != "ok" || p.ResHeader != "Content-Type: text/html" {
		t.Fatal("报文没搬全")
	}
	if p.HEADER != "" {
		t.Fatal("HEADER 本次不进报文表，否则会存两份")
	}
}

// 原对象必须保持原文：Kafka 出口与规则引擎共享同一批指针，且落库排在它们前面
func TestSplitForStore_KeepsOriginalIntact(t *testing.T) {
	big := strings.Repeat("b", payloadMaxBytes+1000)
	origin := &innerbean.WebLog{REQ_UUID: "uuid-2", BODY: big, RES_BODY: "ok"}

	narrow, payloads := splitForStore([]*innerbean.WebLog{origin})

	if narrow[0] == origin {
		t.Fatal("窄行必须是副本，不能就地改原对象")
	}
	if len(origin.BODY) != len(big) || origin.Truncated != 0 {
		t.Fatal("原对象被改动了，Kafka 出口会拿到半截报文")
	}
	if len(payloads[0].BODY) > payloadMaxBytes {
		t.Fatalf("报文没截断，长度 %d", len(payloads[0].BODY))
	}
	if payloads[0].Truncated != 1 || narrow[0].Truncated != 1 {
		t.Fatal("截断标记两边都要有")
	}
}

// 没有 req_uuid 就没法再按主键找回报文，这种日志维持老样子留在 web_logs 列里
func TestSplitForStore_NoUUIDKeepsInline(t *testing.T) {
	origin := &innerbean.WebLog{BODY: "a=1", COOKIES: "sid=x"}

	narrow, payloads := splitForStore([]*innerbean.WebLog{origin})

	if len(payloads) != 0 {
		t.Fatal("没有 req_uuid 不应产出报文行")
	}
	if narrow[0].BODY != "a=1" || narrow[0].COOKIES != "sid=x" {
		t.Fatal("没有 req_uuid 时报文必须留在窄行里，否则就丢了")
	}
}

// 报文列全空不占一行
func TestSplitForStore_SkipsEmptyPayload(t *testing.T) {
	origin := &innerbean.WebLog{REQ_UUID: "uuid-3", URL: "/", SRC_IP: "1.2.3.4", HEADER: "H: 1"}

	narrow, payloads := splitForStore([]*innerbean.WebLog{origin})

	if len(narrow) != 1 {
		t.Fatal("窄行还是要写的")
	}
	if len(payloads) != 0 {
		t.Fatal("报文全空不该占一行")
	}
	if narrow[0].HEADER != "H: 1" {
		t.Fatal("HEADER 留在窄行，不算报文")
	}
}

// 同一 req_uuid 在一批里出现两次（分阶段入队），报文表主键容不下两行，取后到的那条
func TestSplitForStore_DedupByUUID(t *testing.T) {
	first := &innerbean.WebLog{REQ_UUID: "uuid-4", BODY: "a=1"}
	second := &innerbean.WebLog{REQ_UUID: "uuid-4", BODY: "a=1", RES_BODY: "done"}

	narrow, payloads := splitForStore([]*innerbean.WebLog{first, second})

	if len(narrow) != 2 {
		t.Fatal("web_logs 没有主键，两行都照写")
	}
	if len(payloads) != 1 {
		t.Fatalf("报文行应去重成 1 条，实际 %d", len(payloads))
	}
	if payloads[0].RES_BODY != "done" {
		t.Fatal("应保留后到的那条（信息更全）")
	}
}

// nil 条目直接跳过，不能带崩整批
func TestSplitForStore_SkipsNil(t *testing.T) {
	narrow, payloads := splitForStore([]*innerbean.WebLog{nil, {REQ_UUID: "uuid-5", BODY: "x"}})
	if len(narrow) != 1 || len(payloads) != 1 {
		t.Fatalf("nil 应被跳过，实际 %d/%d", len(narrow), len(payloads))
	}
}
