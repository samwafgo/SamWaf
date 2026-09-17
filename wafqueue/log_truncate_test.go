package wafqueue

import (
	"SamWaf/innerbean"
	"strings"
	"testing"
	"unicode/utf8"
)

// 未超长的批次原样返回，不做任何拷贝
func TestTruncateForStore_NoOversize(t *testing.T) {
	logs := []*innerbean.WebLog{
		{BODY: "hello", RES_BODY: "world"},
		{BODY: strings.Repeat("a", payloadMaxBytes)},
	}
	out := truncateForStore(logs)
	if &out[0] != &logs[0] {
		t.Fatal("未超长时不应重新分配切片")
	}
	for i := range out {
		if out[i] != logs[i] {
			t.Fatalf("第 %d 条不应被替换", i)
		}
		if out[i].Truncated != 0 {
			t.Fatalf("第 %d 条不应被标记截断", i)
		}
	}
}

// 超长时截断落库副本，原对象必须保持原文（Kafka 出口与规则引擎共享它）
func TestTruncateForStore_KeepsOriginalIntact(t *testing.T) {
	big := strings.Repeat("b", payloadMaxBytes+1000)
	origin := &innerbean.WebLog{BODY: big, RES_BODY: "ok"}
	logs := []*innerbean.WebLog{origin}

	out := truncateForStore(logs)

	if out[0] == origin {
		t.Fatal("超长条目应换成副本，不能就地改原对象")
	}
	if len(origin.BODY) != len(big) || origin.Truncated != 0 {
		t.Fatal("原对象被改动了，Kafka 出口会拿到半截报文")
	}
	if len(out[0].BODY) > payloadMaxBytes {
		t.Fatalf("副本未被截断，长度 %d", len(out[0].BODY))
	}
	if out[0].Truncated != 1 {
		t.Fatal("副本应标记 Truncated=1")
	}
	if out[0].RES_BODY != "ok" {
		t.Fatal("未超长的列不应被动")
	}
}

// 截断点落在多字节字符中间时要回退到合法边界
func TestCutUTF8_RuneBoundary(t *testing.T) {
	// 每个「中」占 3 字节，构造一个恰好在字符中间被切开的串
	s := strings.Repeat("中", payloadMaxBytes/3+10)
	got := cutUTF8(s)
	if len(got) > payloadMaxBytes {
		t.Fatalf("超出上限: %d", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("截断后不是合法 UTF-8")
	}
	if payloadMaxBytes-len(got) > 3 {
		t.Fatalf("回退过多，丢了 %d 字节", payloadMaxBytes-len(got))
	}
}

// 二进制内容不会被一路回退到空
func TestCutUTF8_BinaryPayload(t *testing.T) {
	s := strings.Repeat("\xff", payloadMaxBytes+100)
	got := cutUTF8(s)
	if len(got) < payloadMaxBytes-3 {
		t.Fatalf("二进制内容回退过多，只剩 %d 字节", len(got))
	}
}

func TestCutBytes(t *testing.T) {
	small := []byte("abc")
	if got := cutBytes(small); len(got) != 3 {
		t.Fatal("未超长的字节切片不应被截")
	}
	big := make([]byte, payloadMaxBytes+10)
	if got := cutBytes(big); len(got) != payloadMaxBytes {
		t.Fatalf("超长字节切片应截到上限，实际 %d", len(got))
	}
}
