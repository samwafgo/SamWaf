package wafqueue

import (
	"unicode/utf8"
)

// payloadMaxBytes 单个报文列落库的字节上限，超出部分丢弃并置 Truncated=1。
const payloadMaxBytes = 64 * 1024

// cutUTF8 按字节上限截断，并回退到合法 UTF-8 边界（最多退 3 字节），
// 免得把多字节字符切成半个，在 utf8mb4 列上落库报错。
// 原文本身是二进制时回退会立即停下，最多多丢 3 字节。
func cutUTF8(s string) string {
	if len(s) <= payloadMaxBytes {
		return s
	}
	cut := s[:payloadMaxBytes]
	for i := 0; i < 3 && len(cut) > 0; i++ {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size > 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut
}

func cutBytes(b []byte) []byte {
	if len(b) <= payloadMaxBytes {
		return b
	}
	return b[:payloadMaxBytes]
}
