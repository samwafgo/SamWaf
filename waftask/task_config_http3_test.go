package waftask

// 回归 issue #916：改了 http3 配置却没有任何代码去起 UDP 监听。
//
// h3 实例只在 StartProxyServer 里创建，而已在监听的端口(Status==0)会被直接跳过，
// 所以配置变更必须显式投递信号让引擎重新对齐；否则页面上开关拨到 1 也只有重启进程才生效。
//
// 这里不启动引擎，只断言 setConfigIntValue 是否往 global.GWAF_CHAN_HTTP3 投了信号。

import (
	"SamWaf/global"
	"testing"
)

// withHTTP3Chan 换一个干净的信号通道，用完还原。
func withHTTP3Chan(t *testing.T) chan int {
	t.Helper()
	old := global.GWAF_CHAN_HTTP3
	ch := make(chan int, 1)
	global.GWAF_CHAN_HTTP3 = ch
	t.Cleanup(func() { global.GWAF_CHAN_HTTP3 = old })
	return ch
}

// withHTTP3Globals 保存/还原两个开关的全局值。
func withHTTP3Globals(t *testing.T) {
	t.Helper()
	oldEnable := global.GCONFIG_ENABLE_HTTP3
	oldBBR := global.GCONFIG_ENABLE_HTTP3_BBR
	t.Cleanup(func() {
		global.GCONFIG_ENABLE_HTTP3 = oldEnable
		global.GCONFIG_ENABLE_HTTP3_BBR = oldBBR
	})
}

func signalCount(ch chan int) int {
	return len(ch)
}

func TestHTTP3ConfigChangeNotifiesEngine(t *testing.T) {
	withHTTP3Globals(t)
	ch := withHTTP3Chan(t)

	setConfigIntValue("http3", 1, 1)

	if global.GCONFIG_ENABLE_HTTP3 != 1 {
		t.Fatalf("GCONFIG_ENABLE_HTTP3 = %d, 期望 1", global.GCONFIG_ENABLE_HTTP3)
	}
	if got := signalCount(ch); got != 1 {
		t.Fatalf("期望投递 1 次引擎对齐信号，实际 %d 次。"+
			"只改全局变量不会让任何端口去监听 UDP(issue #916)", got)
	}
}

// 启动期加载配置(change==0)不得投递信号：那时引擎还没创建、主循环也没起来。
func TestHTTP3InitLoadDoesNotNotify(t *testing.T) {
	withHTTP3Globals(t)
	ch := withHTTP3Chan(t)

	setConfigIntValue("http3", 1, 0)

	if global.GCONFIG_ENABLE_HTTP3 != 1 {
		t.Fatalf("GCONFIG_ENABLE_HTTP3 = %d, 期望 1", global.GCONFIG_ENABLE_HTTP3)
	}
	if got := signalCount(ch); got != 0 {
		t.Fatalf("初始化加载不应投递信号，实际投了 %d 次", got)
	}
}

func TestHTTP3BBRChangeNotifiesEngine(t *testing.T) {
	withHTTP3Globals(t)
	ch := withHTTP3Chan(t)

	setConfigIntValue("http3_bbr", 1, 1)

	if global.GCONFIG_ENABLE_HTTP3_BBR != 1 {
		t.Fatalf("GCONFIG_ENABLE_HTTP3_BBR = %d, 期望 1", global.GCONFIG_ENABLE_HTTP3_BBR)
	}
	if got := signalCount(ch); got != 1 {
		t.Fatalf("拥塞算法变更也需要重建 QUIC 监听，期望投递 1 次信号，实际 %d 次", got)
	}
}

// 赋值必须发生在投递之前，否则消费方可能读到旧值。
func TestHTTP3GlobalAssignedBeforeNotify(t *testing.T) {
	withHTTP3Globals(t)
	ch := withHTTP3Chan(t)

	global.GCONFIG_ENABLE_HTTP3 = 0
	done := make(chan int64, 1)
	go func() {
		<-ch
		done <- global.GCONFIG_ENABLE_HTTP3
	}()

	setConfigIntValue("http3", 1, 1)

	if got := <-done; got != 1 {
		t.Fatalf("消费方读到的全局值是 %d，期望 1（必须先赋值再投递信号）", got)
	}
}

// 连续多次变更只会留一个待处理信号(cap=1 + 非阻塞投递)，且绝不阻塞调用方。
func TestHTTP3NotifyIsNonBlockingAndCoalesced(t *testing.T) {
	withHTTP3Globals(t)
	ch := withHTTP3Chan(t)

	for i := 0; i < 5; i++ {
		setConfigIntValue("http3", int64(i%2), 1)
	}

	if got := signalCount(ch); got != 1 {
		t.Fatalf("期望合并成 1 个待处理信号，实际 %d 个", got)
	}
}
