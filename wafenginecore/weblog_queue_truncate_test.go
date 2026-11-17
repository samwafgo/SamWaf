package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
	"testing"
)

// TestTruncateWebLogBodyForQueue 护栏：日志入队前报文截到记录上限。
// 引擎按检测预算最多读 1MB 喂检测，队列内存/Kafka/文件出口只保留记录上限内的原文。
// 反向验证过：把 truncateWebLogBodyForQueue 改成 no-op 后，截断断言变红。
func TestTruncateWebLogBodyForQueue(t *testing.T) {
	old := global.GCONFIG_RECORD_MAX_BODY_LENGTH
	global.GCONFIG_RECORD_MAX_BODY_LENGTH = 2048
	t.Cleanup(func() { global.GCONFIG_RECORD_MAX_BODY_LENGTH = old })

	big := strings.Repeat("B", 4096)
	weblog := &innerbean.WebLog{BODY: big, SrcByteBody: []byte(big)}
	truncateWebLogBodyForQueue(weblog)
	if len(weblog.BODY) != 2048 {
		t.Fatalf("BODY长度=%d，期望2048", len(weblog.BODY))
	}
	if len(weblog.SrcByteBody) != 2048 {
		t.Fatalf("SrcByteBody长度=%d，期望2048", len(weblog.SrcByteBody))
	}

	// 上限以内的报文原样保留
	small := &innerbean.WebLog{BODY: "abc", SrcByteBody: []byte("def")}
	truncateWebLogBodyForQueue(small)
	if small.BODY != "abc" || string(small.SrcByteBody) != "def" {
		t.Fatal("上限以内的报文被改写")
	}

	// 空对象不崩溃
	truncateWebLogBodyForQueue(nil)
}
