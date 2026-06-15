package wafai

import (
	"bytes"
	"math"
)

// 特征规范 v1
//
// !!! 重要 !!!
// 本文件与 SamWafAI 仓库 samwafai/features/lexical.py 是同一份规范
// （SamWafTechDoc 特征规范 v1）的双语言实现，二者必须逐字节对齐。
// 任何改动（常量/词表/顺序/算法）必须同步修改 Python 侧并升级 FeatureVersion，
// 且重新生成 wafai/testdata/feature_golden.json（uv run samwafai gen-golden）。
const (
	FeatureVersion    = "v1"
	maxComponentBytes = 4096 // 每个分量截断长度
	decodeMax         = 3    // 百分号解码最大迭代次数
	ngramN            = 3    // 字节 n-gram 长度
	ngramBuckets      = 64   // n-gram 哈希桶数量

	scalarFeatureCount = 22
	FeatureCount       = scalarFeatureCount + ngramBuckets // 86
)

// methodIdx HTTP 方法编码（大写比较；未知方法 -> 7）
var methodIdx = map[string]float64{
	"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
	"HEAD": 4, "OPTIONS": 5, "PATCH": 6,
}

const methodIdxOther = 7

// 关键词表（小写；与 Python 侧严格一致）
var (
	kwSQL = [][]byte{
		[]byte("select"), []byte("union"), []byte("insert into"), []byte("update "),
		[]byte("delete from"), []byte("drop table"), []byte("information_schema"),
		[]byte("sleep("), []byte("benchmark("), []byte("load_file"), []byte("group by"),
		[]byte("order by"), []byte("or 1=1"), []byte("' or '"), []byte("\" or \""),
		[]byte("concat("), []byte("char("), []byte("0x"), []byte("xp_"), []byte("exec("),
		[]byte("waitfor delay"), []byte("/*"), []byte("*/"), []byte("--"), []byte("@@"),
	}
	kwXSS = [][]byte{
		[]byte("<script"), []byte("</script"), []byte("javascript:"), []byte("onerror="),
		[]byte("onload="), []byte("onmouseover="), []byte("alert("), []byte("prompt("),
		[]byte("confirm("), []byte("document.cookie"), []byte("document.write"),
		[]byte("eval("), []byte("settimeout("), []byte("fromcharcode"), []byte("<iframe"),
		[]byte("<svg"), []byte("<img"), []byte("expression("), []byte("vbscript:"),
		[]byte("base64,"),
	}
	kwCMD = [][]byte{
		[]byte("/etc/passwd"), []byte("/etc/shadow"), []byte("/bin/sh"), []byte("/bin/bash"),
		[]byte("cmd.exe"), []byte("powershell"), []byte("wget "), []byte("curl "),
		[]byte("chmod "), []byte("nc -e"), []byte("bash -i"), []byte("whoami"),
		[]byte("ipconfig"), []byte("ifconfig"), []byte("&&"), []byte("||"), []byte("$("),
		[]byte("`"), []byte("ping -c"), []byte("net user"), []byte("system("),
		[]byte("passthru("), []byte("shell_exec("), []byte("popen("),
	}
	kwTraversal = [][]byte{
		[]byte("../"), []byte("..\\"), []byte("%2e%2e"), []byte("..%2f"), []byte("..%5c"),
		[]byte("/etc/"), []byte("c:\\"), []byte("c:/"), []byte("web.config"),
		[]byte("boot.ini"), []byte("win.ini"), []byte("/proc/self"), []byte("wp-config"),
	}
	kwProto = [][]byte{
		[]byte("<?php"), []byte("<%"), []byte("${"), []byte("#{"), []byte("{{"),
		[]byte("jndi:"), []byte("ldap://"), []byte("rmi://"), []byte("file://"),
		[]byte("php://"), []byte("data://"), []byte("gopher://"), []byte("dict://"),
		[]byte("expect://"), []byte("phar://"),
	}
	kwScannerUA = [][]byte{
		[]byte("sqlmap"), []byte("nikto"), []byte("nmap"), []byte("acunetix"),
		[]byte("nessus"), []byte("burp"), []byte("dirbuster"), []byte("wfuzz"),
		[]byte("fuzz"), []byte("masscan"), []byte("zgrab"), []byte("python-requests"),
		[]byte("go-http-client"), []byte("curl/"), []byte("wget/"), []byte("libwww"),
	}
)

// FeatureNames 返回特征名顺序（与 Python feature_names() 一致），用于调试/导出。
func FeatureNames() []string {
	names := []string{
		"path_len", "query_len", "body_len", "ua_len",
		"param_count", "max_param_len", "path_depth", "method_idx",
		"special_ratio", "digit_ratio", "letter_ratio", "upper_ratio",
		"nonascii_ratio", "entropy", "decode_layers", "query_eq_count",
		"kw_sql", "kw_xss", "kw_cmd", "kw_traversal", "kw_proto", "kw_scanner_ua",
	}
	for i := 0; i < ngramBuckets; i++ {
		names = append(names, "ngram_"+itoa(i))
	}
	return names
}

// 关键词家族在特征向量中的下标（与 ExtractFeatures 布局一致）
const (
	idxKwSQL       = 16
	idxKwXSS       = 17
	idxKwCMD       = 18
	idxKwTraversal = 19
	idxKwProto     = 20
)

// CategoryHint 依据特征里的关键词家族计数，给 AI 命中一个粗粒度、可读且稳定的
// 类别标签，用于日志展示与"按规则汇总"统计（取值是有限小集合，不会像分数那样发散）。
//
// 注意：这只是基于可疑关键词的启发式标注，模型本身只输出"异常概率"，并不真正分类；
// 该函数是 Go 侧的展示辅助，不参与打分、也不属于特征规范的双语言一致性约束。
func CategoryHint(features []float64) string {
	if len(features) < scalarFeatureCount {
		return "异常请求"
	}
	cats := []struct {
		idx  int
		name string
	}{
		{idxKwSQL, "SQL注入"},
		{idxKwXSS, "XSS"},
		{idxKwCMD, "命令执行"},
		{idxKwTraversal, "目录穿越"},
		{idxKwProto, "注入攻击"},
	}
	best := 0.0
	bestName := ""
	for _, c := range cats {
		if features[c.idx] > best { // 严格大于：并列时保留更高优先级（靠前）的类别
			best = features[c.idx]
			bestName = c.name
		}
	}
	if bestName == "" {
		return "异常请求"
	}
	return bestName
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func truncate(s string) []byte {
	b := []byte(s)
	if len(b) > maxComponentBytes {
		b = b[:maxComponentBytes]
	}
	return b
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// percentDecodeOnce 单次百分号解码：%XX -> 字节；'+' -> 空格；非法 % 序列原样保留。
func percentDecodeOnce(b []byte) []byte {
	out := make([]byte, 0, len(b))
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		if c == '%' && i+2 < n && isHex(b[i+1]) && isHex(b[i+2]) {
			out = append(out, hexVal(b[i+1])<<4|hexVal(b[i+2]))
			i += 3
		} else if c == '+' {
			out = append(out, ' ')
			i++
		} else {
			out = append(out, c)
			i++
		}
	}
	return out
}

// iterDecode 迭代解码至多 decodeMax 次，返回 (解码结果, 实际生效的解码层数)。
func iterDecode(b []byte) ([]byte, int) {
	layers := 0
	cur := b
	for k := 0; k < decodeMax; k++ {
		dec := percentDecodeOnce(cur)
		if bytes.Equal(dec, cur) {
			break
		}
		cur = dec
		layers++
	}
	return cur, layers
}

// asciiLower 仅对 ASCII 'A'-'Z' 转小写（不处理多字节字符）。
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		} else {
			out[i] = c
		}
	}
	return out
}

func fnv1a32(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	ent := 0.0
	for _, cnt := range counts {
		if cnt > 0 {
			p := float64(cnt) / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func isPunct(c byte) bool {
	return (c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) ||
		(c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E)
}

func countKeywords(haystack []byte, kws [][]byte) float64 {
	total := 0
	for _, kw := range kws {
		total += bytes.Count(haystack, kw)
	}
	return float64(total)
}

// ExtractFeatures 提取特征向量（FeatureCount 维，顺序固定，与 Python 一致）。
//
// 入参均为原始字符串（path/query/body 未解码；query 不含 '?'；method 任意大小写）。
func ExtractFeatures(method, path, query, body, userAgent string) []float64 {
	pathB := truncate(path)
	queryB := truncate(query)
	bodyB := truncate(body)
	uaB := truncate(userAgent)

	pathD, l1 := iterDecode(pathB)
	queryD, l2 := iterDecode(queryB)
	bodyD, l3 := iterDecode(bodyB)
	decodeLayers := l1
	if l2 > decodeLayers {
		decodeLayers = l2
	}
	if l3 > decodeLayers {
		decodeLayers = l3
	}

	combined := make([]byte, 0, len(pathD)+len(queryD)+len(bodyD)+2)
	combined = append(combined, pathD...)
	combined = append(combined, '\n')
	combined = append(combined, queryD...)
	combined = append(combined, '\n')
	combined = append(combined, bodyD...)
	combinedLower := asciiLower(combined)
	uaLower := asciiLower(uaB)

	f := make([]float64, FeatureCount)

	// --- 长度/结构类 ---
	f[0] = float64(len(pathB))
	f[1] = float64(len(queryB))
	f[2] = float64(len(bodyB))
	f[3] = float64(len(uaB))

	paramCount := 0
	maxParamLen := 0
	for _, seg := range bytes.Split(queryD, []byte("&")) {
		if len(seg) == 0 {
			continue
		}
		paramCount++
		eq := bytes.IndexByte(seg, '=')
		vlen := 0
		if eq >= 0 {
			vlen = len(seg) - eq - 1
		}
		if vlen > maxParamLen {
			maxParamLen = vlen
		}
	}
	f[4] = float64(paramCount)
	f[5] = float64(maxParamLen)
	f[6] = float64(bytes.Count(pathD, []byte("/")))
	if v, ok := methodIdx[upperASCII(method)]; ok {
		f[7] = v
	} else {
		f[7] = methodIdxOther
	}

	// --- 字符分布类（在 combined 上统计）---
	n := len(combined)
	if n > 0 {
		var punct, digit, letter, upper, nonascii int
		for _, c := range combined {
			if isPunct(c) {
				punct++
			}
			if c >= '0' && c <= '9' {
				digit++
			}
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				letter++
			}
			if c >= 'A' && c <= 'Z' {
				upper++
			}
			if c >= 0x80 {
				nonascii++
			}
		}
		fn := float64(n)
		f[8] = float64(punct) / fn
		f[9] = float64(digit) / fn
		f[10] = float64(letter) / fn
		f[11] = float64(upper) / fn
		f[12] = float64(nonascii) / fn
	}
	f[13] = entropy(combined)
	f[14] = float64(decodeLayers)
	f[15] = float64(bytes.Count(queryD, []byte("=")))

	// --- 关键词类 ---
	f[16] = countKeywords(combinedLower, kwSQL)
	f[17] = countKeywords(combinedLower, kwXSS)
	f[18] = countKeywords(combinedLower, kwCMD)
	f[19] = countKeywords(combinedLower, kwTraversal)
	f[20] = countKeywords(combinedLower, kwProto)
	f[21] = countKeywords(uaLower, kwScannerUA)

	// --- 字节 3-gram 哈希桶频率 ---
	ln := len(combinedLower)
	if ln >= ngramN {
		var counts [ngramBuckets]int
		totalNgrams := ln - ngramN + 1
		for i := 0; i < totalNgrams; i++ {
			h := fnv1a32(combinedLower[i : i+ngramN])
			counts[h%ngramBuckets]++
		}
		for bi := 0; bi < ngramBuckets; bi++ {
			f[scalarFeatureCount+bi] = float64(counts[bi]) / float64(totalNgrams)
		}
	}

	return f
}

func upperASCII(s string) string {
	b := []byte(s)
	changed := false
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
			changed = true
		}
	}
	if !changed {
		return s
	}
	return string(b)
}
