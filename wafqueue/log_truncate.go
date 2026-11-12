package wafqueue

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// payloadMaxBytes 为各数据库报文列共用的字节上限。
const payloadMaxBytes = 64*1024 - 1

func cutUTF8(s string) string {
	return cutUTF8N(s, payloadMaxBytes)
}

// cutUTF8N 仅处理落库文本副本，按完整 UTF-8 字符截取。
func cutUTF8N(s string, max int) string {
	if max <= 0 {
		return ""
	}
	s = cleanPersistedText(s)
	if len(s) <= max {
		return s
	}
	end := max
	for !utf8.RuneStart(s[end]) {
		end--
	}
	return strings.Clone(s[:end])
}

func cleanPersistedText(s string) string {
	originalSize := len(s)
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) < originalSize {
		return strings.Clone(s)
	}
	return s
}

func cutTextCharsN(s string, max int) string {
	if max <= 0 {
		return ""
	}
	s = cleanPersistedText(s)
	count := 0
	for pos := range s {
		if count == max {
			return strings.Clone(s[:pos])
		}
		count++
	}
	return s
}

func cutBytes(b []byte) []byte {
	return cutBytesN(b, payloadMaxBytes)
}

func cutBytesN(b []byte, max int) []byte {
	if max <= 0 {
		return nil
	}
	if len(b) > max {
		b = b[:max]
	}
	return bytes.Clone(b)
}

func persistedBodyLimit(configured int64) int {
	if configured > 0 && configured < int64(payloadMaxBytes) {
		return int(configured)
	}
	return payloadMaxBytes
}
