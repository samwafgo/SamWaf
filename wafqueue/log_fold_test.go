package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"testing"
)

// 折叠过滤器的纯逻辑用例。直接改全局上限模拟配置热加载，用例间恢复。
func resetFold(limit int64) func() {
	saved := global.GCONFIG_LOG_FOLD_PER_MINUTE
	global.GCONFIG_LOG_FOLD_PER_MINUTE = limit
	return func() { global.GCONFIG_LOG_FOLD_PER_MINUTE = saved }
}

func mkEvent(uuid, ip, rule string, unix int64) *innerbean.WebLog {
	lg := mkLog(uuid, ip)
	lg.ACTION = "阻止"
	lg.RULE = rule
	lg.UNIX_ADD_TIME = unix
	return lg
}

// 同一键一个窗口内只放行前 K 条；正常请求不折叠。
// UNIX_ADD_TIME 生产侧是毫秒（引擎入队 UnixNano()/1e6），用例一律按毫秒构造；
// base 对齐到整分钟起点（1699999980000 % 60000 == 0），+60000 恰好换窗。
const foldTestBase = int64(1699999980000)

func TestFold_FirstKKept(t *testing.T) {
	defer resetFold(3)()
	f := newLogFoldFilter(100)
	base := foldTestBase

	logs := []*innerbean.WebLog{
		mkEvent("a", "1.1.1.1", "SQLi", base+1000),
		mkEvent("b", "1.1.1.1", "SQLi", base+2000),
		mkEvent("c", "1.1.1.1", "SQLi", base+3000),
		mkEvent("d", "1.1.1.1", "SQLi", base+4000), // 第4条：折叠
		mkLog("n1", "1.1.1.1"),                     // 正常请求：任何档位都放行
		mkEvent("e", "2.2.2.2", "SQLi", base+5000), // 不同IP：独立配额
		mkEvent("f", "1.1.1.1", "XSS", base+6000),  // 不同规则：独立配额
	}
	kept := f.filterForStore(logs)

	if len(kept) != 6 {
		t.Fatalf("应保留6条（3事件+1正常+1异IP+1异规则），实际 %d", len(kept))
	}
	for _, lg := range kept {
		if lg.REQ_UUID == "d" {
			t.Fatal("第4条同类事件应被折叠")
		}
	}
	// 原数组不能被改写：统计/CC/出口还要拿全量
	if len(logs) != 7 || logs[3].REQ_UUID != "d" {
		t.Fatal("filterForStore 不得改动入参数组内容")
	}
}

// 换分钟窗口后配额重新计数（窗口 60 秒）
func TestFold_WindowReset(t *testing.T) {
	defer resetFold(1)()
	f := newLogFoldFilter(100)
	min1 := foldTestBase
	min2 := min1 + 60000

	if got := f.filterForStore([]*innerbean.WebLog{mkEvent("a", "1.1.1.1", "SQLi", min1)}); len(got) != 1 {
		t.Fatal("窗口内第1条应放行")
	}
	if got := f.filterForStore([]*innerbean.WebLog{mkEvent("b", "1.1.1.1", "SQLi", min1+59000)}); len(got) != 0 {
		t.Fatal("同窗口第2条应被折叠")
	}
	if got := f.filterForStore([]*innerbean.WebLog{mkEvent("c", "1.1.1.1", "SQLi", min2)}); len(got) != 1 {
		t.Fatal("新窗口第1条应重新放行")
	}
}

// 折叠关闭（0）时一律放行
func TestFold_Disabled(t *testing.T) {
	defer resetFold(0)()
	f := newLogFoldFilter(100)
	for i := 0; i < 10; i++ {
		if got := f.filterForStore([]*innerbean.WebLog{mkEvent("x", "1.1.1.1", "SQLi", 1700000000000)}); len(got) != 1 {
			t.Fatal("关闭折叠后每条都应放行")
		}
	}
}

// 键数封顶后，没见过的键直接放行（宁多记不漏记）
func TestFold_KeyCapFallsOpen(t *testing.T) {
	defer resetFold(1)()
	f := newLogFoldFilter(2)
	min := foldTestBase

	kept := f.filterForStore([]*innerbean.WebLog{
		mkEvent("a", "1.1.1.1", "SQLi", min),
		mkEvent("b", "2.2.2.2", "SQLi", min),
		mkEvent("c", "3.3.3.3", "SQLi", min), // 第3个键，超上限：放行
		mkEvent("d", "1.1.1.1", "SQLi", min), // 老键第2条：折叠
	})
	if len(kept) != 3 {
		t.Fatalf("封顶后新键应放行、老键仍折叠，实际保留 %d 条", len(kept))
	}
	for _, lg := range kept {
		if lg.REQ_UUID == "d" {
			t.Fatal("老键超额仍应折叠")
		}
	}
}

// 运行时把上限调小：过滤器立即按新上限执行（已计数的清零重算，新窗口语义一致）
func TestFold_LimitReload(t *testing.T) {
	defer resetFold(5)()
	f := newLogFoldFilter(100)
	min := foldTestBase

	f.filterForStore([]*innerbean.WebLog{
		mkEvent("a", "1.1.1.1", "SQLi", min),
		mkEvent("b", "1.1.1.1", "SQLi", min),
	})
	global.GCONFIG_LOG_FOLD_PER_MINUTE = 1
	kept := f.filterForStore([]*innerbean.WebLog{
		mkEvent("c", "1.1.1.1", "SQLi", min),
		mkEvent("d", "9.9.9.9", "SQLi", min),
	})
	if len(kept) != 2 || kept[0].REQ_UUID != "c" || kept[1].REQ_UUID != "d" {
		t.Fatalf("上限热改后计数清零：本键新配额第1条与全新键都应放行，实际 %+v", kept)
	}
	// 新配额已用掉：同键再来折叠，别的键不受影响
	kept = f.filterForStore([]*innerbean.WebLog{
		mkEvent("e", "1.1.1.1", "SQLi", min),
		mkEvent("f", "8.8.8.8", "SQLi", min),
	})
	if len(kept) != 1 || kept[0].REQ_UUID != "f" {
		t.Fatalf("新配额用完后同键应折叠、异键放行，实际 %+v", kept)
	}
}

// 关（0）再开（>0）之后折叠必须恢复：上限同步不能落在 limit<=0 早退之后。
// 这是压测场景3（fold 0→5 切换后折叠失效、队列再次积压）抓出来的回归路径。
func TestFold_ReenableAfterDisable(t *testing.T) {
	defer resetFold(5)()
	f := newLogFoldFilter(100)
	min := foldTestBase

	global.GCONFIG_LOG_FOLD_PER_MINUTE = 0
	if got := f.filterForStore([]*innerbean.WebLog{mkEvent("a", "1.1.1.1", "SQLi", min)}); len(got) != 1 {
		t.Fatal("关闭期间应全放行")
	}
	global.GCONFIG_LOG_FOLD_PER_MINUTE = 2
	kept := f.filterForStore([]*innerbean.WebLog{
		mkEvent("b", "1.1.1.1", "SQLi", min),
		mkEvent("c", "1.1.1.1", "SQLi", min),
		mkEvent("d", "1.1.1.1", "SQLi", min),
	})
	if len(kept) != 2 || kept[0].REQ_UUID != "b" || kept[1].REQ_UUID != "c" {
		t.Fatalf("重新开启后应恢复折叠（前2放行第3折叠），实际 %+v", kept)
	}
}
