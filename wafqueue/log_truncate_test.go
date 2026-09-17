package wafqueue

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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
