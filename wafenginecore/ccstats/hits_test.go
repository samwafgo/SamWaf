package ccstats

import (
	"strconv"
	"testing"
)

func TestRecord_CountsAndActions(t *testing.T) {
	tr := New()
	tr.Record("r1", "captcha", "1.1.1.1")
	tr.Record("r1", "captcha", "1.1.1.1")
	tr.Record("r1", "ban", "2.2.2.2")
	tr.Record("r2", "deny", "3.3.3.3")

	counts := tr.Counts()
	if counts["r1"] != 3 || counts["r2"] != 1 {
		t.Fatalf("触发总数不对: %v", counts)
	}
	b := tr.Board("r1", 10)
	if b.ByAction["captcha"] != 2 || b.ByAction["ban"] != 1 {
		t.Fatalf("按动作分布不对: %v", b.ByAction)
	}
	if b.FirstAt == 0 || b.LastAt == 0 {
		t.Fatalf("首末触发时间应被记录")
	}
}

// 看板的价值就在排序：谁打得最狠要排最前。
func TestBoard_SortedByCountDesc(t *testing.T) {
	tr := New()
	for i := 0; i < 5; i++ {
		tr.Record("r", "deny", "low")
	}
	for i := 0; i < 50; i++ {
		tr.Record("r", "deny", "high")
	}
	for i := 0; i < 20; i++ {
		tr.Record("r", "deny", "mid")
	}
	b := tr.Board("r", 10)
	if len(b.Clients) != 3 {
		t.Fatalf("应有 3 个客户端，实际 %d", len(b.Clients))
	}
	want := []string{"high", "mid", "low"}
	for i, w := range want {
		if b.Clients[i].DimValue != w {
			t.Fatalf("第 %d 位应是 %s，实际 %s", i, w, b.Clients[i].DimValue)
		}
	}
	if b.Clients[0].Count != 50 {
		t.Fatalf("次数不对: %d", b.Clients[0].Count)
	}
}

func TestBoard_TopNLimit(t *testing.T) {
	tr := New()
	for i := 0; i < 30; i++ {
		tr.Record("r", "deny", "ip"+strconv.Itoa(i))
	}
	if b := tr.Board("r", 5); len(b.Clients) != 5 {
		t.Fatalf("应截断到 5 条，实际 %d", len(b.Clients))
	}
	if b := tr.Board("r", 0); len(b.Clients) != 30 {
		t.Fatalf("topN<=0 应用默认值 %d，实际返回 %d", TopDefault, len(b.Clients))
	}
}

// 客户端表有天花板：被打的时候攻击者可以换着 IP 来，不封顶就是一条内存膨胀路径。
// 满了之后不再收录新客户端，且必须如实标记已截断——
// 界面上写着「TOP 50」而实际漏了一半，比不显示更糟。
func TestRecord_ClientCapAndTruncated(t *testing.T) {
	tr := New()
	for i := 0; i < maxClientsPerRule+50; i++ {
		tr.Record("r", "deny", "ip"+strconv.Itoa(i))
	}
	b := tr.Board("r", 1000)
	if len(b.Clients) != maxClientsPerRule {
		t.Fatalf("客户端数应封顶在 %d，实际 %d", maxClientsPerRule, len(b.Clients))
	}
	if !b.Truncated {
		t.Fatalf("超出上限后必须标记 truncated，否则界面会把不完整的数据当成全部")
	}
	// 总数不受客户端表上限影响：没被收录的那些请求仍然真实发生过
	if b.Total != int64(maxClientsPerRule+50) {
		t.Fatalf("触发总数应为 %d，实际 %d", maxClientsPerRule+50, b.Total)
	}
	// 已收录的客户端继续累加，不因表满而停止计数
	tr.Record("r", "deny", "ip0")
	if got := tr.Board("r", 1000); got.Clients[0].DimValue != "ip0" || got.Clients[0].Count != 2 {
		t.Fatalf("表满后已收录的客户端应继续累加，实际 %+v", got.Clients[0])
	}
}

func TestRecord_RuleCap(t *testing.T) {
	tr := New()
	for i := 0; i < maxRules+10; i++ {
		tr.Record("r"+strconv.Itoa(i), "deny", "1.1.1.1")
	}
	if got := len(tr.Counts()); got != maxRules {
		t.Fatalf("规则数应封顶在 %d，实际 %d", maxRules, got)
	}
}

// 查不到的规则返回全零结果而不是 nil：
// 「查得到但都是 0」和「查不到」对用户是两件事，接口层不该把它们混成一个。
func TestBoard_UnknownRuleReturnsZeroed(t *testing.T) {
	b := New().Board("nope", 10)
	if b.Total != 0 || b.Clients == nil || b.ByAction == nil {
		t.Fatalf("未触发过的规则应返回各项为零的结果，实际 %+v", b)
	}
}

func TestDropAndReset(t *testing.T) {
	tr := New()
	tr.Record("r1", "deny", "1.1.1.1")
	tr.Record("r2", "deny", "1.1.1.1")
	tr.Drop("r1")
	if _, ok := tr.Counts()["r1"]; ok {
		t.Fatalf("Drop 后不应还留着该规则")
	}
	if tr.Counts()["r2"] != 1 {
		t.Fatalf("Drop 不应影响其它规则")
	}
	tr.Reset()
	if len(tr.Counts()) != 0 {
		t.Fatalf("Reset 后应清空")
	}
}

// 空维度值不该被当成一个客户端：所有取不到维度的请求会挤在同一个空键上，
// 看板上显示成「某个客户端打了几万次」，那是假的。
func TestRecord_EmptyDimValueNotCounted(t *testing.T) {
	tr := New()
	tr.Record("r", "deny", "")
	b := tr.Board("r", 10)
	if b.Total != 1 {
		t.Fatalf("触发总数仍应记 1，实际 %d", b.Total)
	}
	if len(b.Clients) != 0 {
		t.Fatalf("空维度值不应进客户端表，实际 %+v", b.Clients)
	}
}
