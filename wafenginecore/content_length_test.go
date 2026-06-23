package wafenginecore

import "testing"

// TestSanitizeContentLength 验证 chunked/未知长度场景下 ContentLength 的归一逻辑。
// Go 的 http.Request.ContentLength / http.Response.ContentLength 在分块传输(chunked)
// 等长度未知时为 -1，若直接累加进流量统计会导致出现负数（如出站 -69 KB）。
func TestSanitizeContentLength(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want int64
	}{
		{"chunked未知长度返回-1应归零", -1, 0},
		{"任意负数都归零", -12345, 0},
		{"零保持零", 0, 0},
		{"正常字节数原样返回", 273, 273},
		{"大文件字节数原样返回", 10 * 1024 * 1024, 10 * 1024 * 1024},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeContentLength(c.in); got != c.want {
				t.Fatalf("sanitizeContentLength(%d) = %d, 期望 %d", c.in, got, c.want)
			}
		})
	}
}

// TestSanitizeContentLength_SumNeverNegative 模拟统计采集器对一批日志的累加：
// 即使上游全部为 chunked(-1)，归一后累加结果也不会出现负数。
func TestSanitizeContentLength_SumNeverNegative(t *testing.T) {
	// 模拟 5 条 chunked 响应（原始 ContentLength 均为 -1）
	rawContentLengths := []int64{-1, -1, -1, -1, -1}

	var sumRaw int64
	var sumSanitized int64
	for _, n := range rawContentLengths {
		sumRaw += n
		sumSanitized += sanitizeContentLength(n)
	}

	if sumRaw >= 0 {
		t.Fatalf("前置假设失败：原始累加应为负数，实际 %d", sumRaw)
	}
	if sumSanitized < 0 {
		t.Fatalf("归一后累加出现负数：%d", sumSanitized)
	}
	if sumSanitized != 0 {
		t.Fatalf("5 条 chunked 响应归一后应累加为 0，实际 %d", sumSanitized)
	}
}
