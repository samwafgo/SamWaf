package wafenginecore

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"testing"
)

// gzipBytes 把 payload 压成 gzip 流（高重复内容压缩比极高，容器很小）。
func gzipCompressBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestDecompressRequestContentCapped 护栏：压缩报文的解压结果读取必须封顶，
// 高压缩比报文不能把内存放大成解压后的完整大小；传 0 保持不限制（缓存完整内容语义）。
// 反向验证过：把 content_encoding.go 里的 LimitReader 读法换回无上限 io.ReadAll 后，
// 10MB 封顶用例拿到完整 20MB、用例变红。
func TestDecompressRequestContentCapped(t *testing.T) {
	waf := &WafEngine{}
	decompressed := bytes.Repeat([]byte("A"), 20<<20) // 20 MB
	compressed := gzipCompressBytes(t, decompressed)

	// 检测语义：10MB 封顶，超出截断
	req := httptest.NewRequest(http.MethodPost, "http://xxxx.com/", bytes.NewReader(compressed))
	req.Header.Set("Content-Encoding", "gzip")
	got, err := waf.decompressRequestContent(req, 10<<20)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if int64(len(got)) != 10<<20 {
		t.Fatalf("解压结果未封顶: %d字节，期望%d", len(got), 10<<20)
	}
	if !bytes.Equal(got, decompressed[:10<<20]) {
		t.Fatal("截断前缀与原文不一致")
	}

	// 缓存语义：传 0 不限制，完整解压
	req2 := httptest.NewRequest(http.MethodPost, "http://xxxx.com/", bytes.NewReader(compressed))
	req2.Header.Set("Content-Encoding", "gzip")
	full, err := waf.decompressRequestContent(req2, 0)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if !bytes.Equal(full, decompressed) {
		t.Fatalf("不限制时应完整解压: %d字节，期望%d", len(full), len(decompressed))
	}
}

// TestReadBodyDecompressFailFallbackBounded 护栏：解压失败的回退分支只读检测预算内的前缀，
// 剩余原始流拼回 r.Body，转发完整。
func TestReadBodyDecompressFailFallbackBounded(t *testing.T) {
	raw := bytes.Repeat([]byte("not-gzip-data"), 200<<10) // 约 2.6MB 非法 gzip 流
	req := httptest.NewRequest(http.MethodPost, "http://xxxx.com/upload", bytes.NewReader(raw))
	req.Header.Set("Content-Encoding", "gzip")
	waf := &WafEngine{}

	got := waf.readRequestBodyForDetect(req, false)
	if int64(len(got)) != detectBodyReadLimit {
		t.Fatalf("回退分支读取长度=%d，期望封顶%d", len(got), detectBodyReadLimit)
	}
	if !bytes.Equal(got, raw[:detectBodyReadLimit]) {
		t.Fatal("回退前缀与原始报文不一致")
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, raw) {
		t.Fatalf("回退分支转发不完整: 读到%d字节，期望%d字节", len(rest), len(raw))
	}
}

// TestReadBodyDecompressFailFallbackNoFullCopy 护栏：解压失败的回退分支不得把
// 已落内存的原始流再整份复制一遍（峰值内存翻倍）。
// 判定方式：先实测同尺寸流的单次 ReadAll 分配量作为基线（解压函数内部的
// 原始读取本身就要这么多），被测路径的分配量不应明显超过 1.5 份基线——
// 固定实现只多读 1MB 前缀，缺陷实现会再整份复制原始流。
// 反向验证过：把回退分支改回 io.ReadAll 全量读后，分配量超过 1.5 份基线、用例变红。
func TestReadBodyDecompressFailFallbackNoFullCopy(t *testing.T) {
	rawLen := 50 << 20
	raw := bytes.Repeat([]byte("x"), rawLen) // 50MB 非法 gzip 流

	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	// 基线：同尺寸流的单次 ReadAll 分配量
	var b0, m0 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&b0)
	ref, _ := io.ReadAll(bytes.NewReader(raw))
	runtime.ReadMemStats(&m0)
	baseline := int(m0.TotalAlloc - b0.TotalAlloc)
	_ = ref

	req := httptest.NewRequest(http.MethodPost, "http://xxxx.com/upload", bytes.NewReader(raw))
	req.Header.Set("Content-Encoding", "gzip")
	waf := &WafEngine{}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	waf.readRequestBodyForDetect(req, false)
	runtime.ReadMemStats(&after)

	delta := int(after.TotalAlloc - before.TotalAlloc)
	if delta > baseline+baseline/2+(10<<20) {
		t.Fatalf("解压失败回退分支整份复制了原始流: 额外分配%d字节，单份基线%d字节", delta, baseline)
	}
}
