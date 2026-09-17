package wafqueue

import (
	"SamWaf/innerbean"
	"unicode/utf8"
)

// payloadMaxBytes 单个报文列落库的字节上限，超出部分丢弃并置 Truncated=1。
const payloadMaxBytes = 64 * 1024

// truncateForStore 返回用于落库的日志切片：超长报文列在副本上截断，未超长的元素原样复用。
//
// 关键点是不改原对象——Kafka 出口与规则引擎共享同一批指针，且落库在它们之前执行，
// 就地截断会让下游也只能拿到半截报文。整批都没超长时直接返回原切片，不额外分配。
func truncateForStore(logs []*innerbean.WebLog) []*innerbean.WebLog {
	out := logs
	copied := false
	for i, lg := range logs {
		if lg == nil || !needTruncate(lg) {
			continue
		}
		if !copied {
			out = make([]*innerbean.WebLog, len(logs))
			copy(out, logs)
			copied = true
		}
		c := *lg
		c.BODY = cutUTF8(c.BODY)
		c.RES_BODY = cutUTF8(c.RES_BODY)
		c.POST_FORM = cutUTF8(c.POST_FORM)
		c.HEADER = cutUTF8(c.HEADER)
		c.COOKIES = cutUTF8(c.COOKIES)
		c.ResHeader = cutUTF8(c.ResHeader)
		c.SrcByteBody = cutBytes(c.SrcByteBody)
		c.SrcByteResBody = cutBytes(c.SrcByteResBody)
		c.Truncated = 1
		out[i] = &c
	}
	return out
}

func needTruncate(lg *innerbean.WebLog) bool {
	return len(lg.BODY) > payloadMaxBytes ||
		len(lg.RES_BODY) > payloadMaxBytes ||
		len(lg.POST_FORM) > payloadMaxBytes ||
		len(lg.HEADER) > payloadMaxBytes ||
		len(lg.COOKIES) > payloadMaxBytes ||
		len(lg.ResHeader) > payloadMaxBytes ||
		len(lg.SrcByteBody) > payloadMaxBytes ||
		len(lg.SrcByteResBody) > payloadMaxBytes
}

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
