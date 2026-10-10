package wafqueue

import (
	"SamWaf/global"
	"testing"
)

// 在线表未就绪时发通知不能 panic。
// 曾经的现象：消息消费协程早于 global.GWebSocket 赋值启动，启动期广播一次就对 nil 调方法，
// 协程崩溃后被 NeverExit 拉起，日志里留一段 nil pointer dereference 堆栈。
func TestSendToWebSocket_NilOnlineTable(t *testing.T) {
	saved := global.GWebSocket
	global.GWebSocket = nil
	defer func() {
		global.GWebSocket = saved
		if r := recover(); r != nil {
			t.Fatalf("在线表为 nil 时不应 panic: %v", r)
		}
	}()

	sendToWebSocket("测试通知", "内容", nil, "Test")
}
