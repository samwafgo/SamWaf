package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
	"testing"
)

// TestExtractPayloadTruncatesBodyAtRecordLimit 护栏：检测输入可以远长于日志上限
// （引擎按检测预算最多读取 1MB 前缀喂给检测），但落库报文必须仍按
// GCONFIG_RECORD_MAX_BODY_LENGTH 截断，且引擎侧的原文不被改写。
// 反向验证过：把 extractPayload 的 body 截断上限改成检测预算后，截断断言变红。
func TestExtractPayloadTruncatesBodyAtRecordLimit(t *testing.T) {
	old := global.GCONFIG_RECORD_MAX_BODY_LENGTH
	global.GCONFIG_RECORD_MAX_BODY_LENGTH = 2048
	t.Cleanup(func() { global.GCONFIG_RECORD_MAX_BODY_LENGTH = old })

	// 模拟引擎侧检测输入：日志上限两倍长的报文
	full := strings.Repeat("A", 4096)
	lg := &innerbean.WebLog{
		REQ_UUID:    "uuid-test",
		HOST_CODE:   "host-test",
		BODY:        full,
		SrcByteBody: []byte(full),
		Day:         20261117,
	}

	p := extractPayload(lg, "attack")
	if p == nil {
		t.Fatal("报文行不应为空")
	}
	if len(p.BODY) > 2048 {
		t.Fatalf("落库BODY长度=%d，期望不超过记录上限2048", len(p.BODY))
	}
	if p.Truncated != 1 {
		t.Fatalf("发生截断时Truncated应为1，得到%d", p.Truncated)
	}
	// 引擎侧原文保持完整（检测输入不被落库截断反噬）
	if lg.BODY != full || string(lg.SrcByteBody) != full {
		t.Fatal("extractPayload改写了引擎侧原文")
	}
	// 短报文不标记截断
	short := &innerbean.WebLog{REQ_UUID: "u2", HOST_CODE: "h2", BODY: "abc", Day: 20261117}
	if sp := extractPayload(short, "access"); sp == nil || sp.Truncated != 0 {
		t.Fatalf("短报文不应标记截断: %+v", sp)
	}
}
