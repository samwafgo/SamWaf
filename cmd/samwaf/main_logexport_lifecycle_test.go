package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGracefulStopsLogExportBeforeEngineShutdown(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "func (m *wafSystenService) Graceful()")
	if start < 0 {
		t.Fatal("Graceful 函数不存在")
	}
	block := text[start:]
	end := strings.Index(block, "\nfunc ")
	if end > 0 {
		block = block[:end]
	}
	stopAt := strings.Index(block, "logExportWorkerLifecycle.stop(")
	engineAt := strings.Index(block, "m.stopSamWaf()")
	if stopAt < 0 || engineAt < 0 || stopAt > engineAt {
		t.Fatalf("导出执行器必须先于引擎关闭停止: stop=%d engine=%d", stopAt, engineAt)
	}
}

func TestLogExportLifecycleBlocksActivateAfterStopBegins(t *testing.T) {
	releaseStop := make(chan struct{})
	stopEntered := make(chan struct{})
	started := make(chan struct{}, 2)
	var l workerLogExportLifecycle
	go l.stop(func() {
		close(stopEntered) // 该标记由下面的断言读取；Stop 真正返回前阻塞在 releaseStop
		<-releaseStop
	})

	// 等待 Stop 已经拿到生命周期锁，模拟旧 Worker 正在等待导出协程退出。
	select {
	case <-stopEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop 未进入")
	}

	go l.start(func() { started <- struct{}{} })
	select {
	case <-started:
		t.Fatal("停止过程中仍接受 ACTIVATE 启动导出执行器")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseStop)

	// 停止完成后再来的 ACTIVATE 也必须被拒绝。
	l.start(func() { started <- struct{}{} })
	select {
	case <-started:
		t.Fatal("停止完成后仍接受 ACTIVATE 启动导出执行器")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestLogExportLifecycleStopOnlyOnce(t *testing.T) {
	var l workerLogExportLifecycle
	var calls int
	var mu sync.Mutex
	stop := func() {
		mu.Lock()
		calls++
		mu.Unlock()
	}
	l.stop(stop)
	l.stop(stop)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("Stop 应只执行一次，实际 %d 次", calls)
	}
}
