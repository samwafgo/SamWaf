package wafqueue

import (
	"SamWaf/innerbean"
	"testing"
)

func TestSampleReservoirCap(t *testing.T) {
	r := &sampleReservoir{buckets: map[string]*sampleBucket{}}
	for i := 0; i < 10000; i++ {
		r.Pick(&innerbean.WebLog{HOST_CODE: "h1", Day: 20260901, REQ_UUID: itoa(i), BODY: "x"})
	}
	picks := r.snapshot()
	if len(picks) != sampleNegPerSiteDay {
		t.Fatalf("池子上限应恒为 %d，实际 %d", sampleNegPerSiteDay, len(picks))
	}
	// 池内不得有重复 req_uuid
	seen := map[string]bool{}
	for _, p := range picks {
		if seen[p.ReqUUID] {
			t.Fatalf("池内出现重复 %s", p.ReqUUID)
		}
		seen[p.ReqUUID] = true
		if p.Kind != PayloadKindSample {
			t.Fatalf("负样本 kind 应为 sample，实际 %q", p.Kind)
		}
	}
	// 采中的条目把池子标脏，FlushIfDue 才会落库
	b := r.buckets["h1|20260901"]
	if !b.dirty {
		t.Fatal("有采中的条目池子应标脏")
	}
}

// 前 N 条必中；报文全空的不采（空报文对 AI 训练没有价值）
func TestSampleReservoirFirstNAndEmpty(t *testing.T) {
	r := &sampleReservoir{buckets: map[string]*sampleBucket{}}
	for i := 0; i < sampleNegPerSiteDay; i++ {
		if !r.Pick(&innerbean.WebLog{HOST_CODE: "h1", Day: 20260901, REQ_UUID: itoa(i), BODY: "x"}) {
			t.Fatalf("前 %d 条必须全中，第 %d 条漏了", sampleNegPerSiteDay, i+1)
		}
	}
	if r.Pick(&innerbean.WebLog{HOST_CODE: "h1", Day: 20260901, REQ_UUID: "empty"}) {
		t.Fatal("报文全空的请求不该占负样本配额")
	}
}

func TestSampleReservoirPerSitePerDay(t *testing.T) {
	r := &sampleReservoir{buckets: map[string]*sampleBucket{}}
	for i := 0; i < sampleNegPerSiteDay; i++ {
		r.Pick(&innerbean.WebLog{HOST_CODE: "h1", Day: 20260901, BODY: "x"})
	}
	if !r.Pick(&innerbean.WebLog{HOST_CODE: "h2", Day: 20260901, BODY: "x"}) {
		t.Fatal("另一个站点的第一条必须采中（各自独立）")
	}
	// 新的一天到来后，更早的 bucket 被清（用两个都早于今天的日期，免得依赖真实日期）
	r.Pick(&innerbean.WebLog{HOST_CODE: "h1", Day: 20260902, BODY: "x"})
	for k := range r.buckets {
		if k == "h1|20260901" {
			t.Fatal("新的一天到来后，更早的 bucket 应被清掉")
		}
	}
}
