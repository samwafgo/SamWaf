package wafqueue

import (
	"strconv"
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

func TestCutUTF8_InvalidText(t *testing.T) {
	s := "start\x00" + strings.Repeat("\xff", payloadMaxBytes+100) + "结束�"
	if got := cutUTF8(s); got != "start结束�" {
		t.Fatalf("文本规范化结果不符: %q", got)
	}
}

func TestCutUTF8_MySQLTextBoundary(t *testing.T) {
	for _, size := range []int{65534, 65535, 65536, 70000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			got := cutUTF8(strings.Repeat("a", size))
			want := size
			if want > 65535 {
				want = 65535
			}
			if len(got) != want {
				t.Fatalf("input=%d: got=%d, want=%d", size, len(got), want)
			}
		})
	}
}

func TestCutUTF8N_Boundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		max   int
		want  string
	}{
		{"zero", "abc", 0, ""},
		{"negative", "abc", -1, ""},
		{"short rune", "中a", 2, ""},
		{"whole rune", "中a", 3, "中"},
		{"mixed", "ab中c", 4, "ab"},
		{"clean before limit", "a\x00\xff中b", 4, "a中"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cutUTF8N(tc.input, tc.max); got != tc.want {
				t.Fatalf("got=%q, want=%q", got, tc.want)
			}
		})
	}
}

func TestCutBytes(t *testing.T) {
	small := []byte("abc")
	smallCopy := cutBytes(small)
	if len(smallCopy) != 3 {
		t.Fatal("未超长的字节切片不应被截")
	}
	smallCopy[0] = 'x'
	if string(small) != "abc" {
		t.Fatal("short bytes must have independent storage")
	}
	for _, max := range []int{-1, 0} {
		if got := cutBytesN(small, max); len(got) != 0 {
			t.Fatal("non-positive byte limit must return no data")
		}
	}
	big := make([]byte, payloadMaxBytes+10)
	got := cutBytes(big)
	if len(got) != payloadMaxBytes {
		t.Fatalf("超长字节切片应截到上限，实际 %d", len(got))
	}
	got[0] = 1
	if big[0] != 0 {
		t.Fatal("clipped bytes must have independent storage")
	}
}
