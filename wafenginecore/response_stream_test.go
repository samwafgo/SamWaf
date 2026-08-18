package wafenginecore

import (
	"SamWaf/innerbean"
	"bytes"
	"io"
	"strings"
	"testing"
)

// StreamProcessor 的字节级保真用例。
//
// 锁的是 issue #949 / #954：SamWaf 反代 text/event-stream 时，客户端收到首段内容后
// 连接在 response.completed 之前被断开，Codex 报
// "stream disconnected before completion: stream closed before response.completed"。
//
// 根因不在超时、不在 record_resp、也不在响应体大小限制，而在 process_stream.go 的 Read()：
// 它把"处理完但一次没塞下"的数据塞回原始 buffer，并在上游返回 (0, io.EOF) 时
// 把没交付的部分整段丢掉 —— 单条 SSE 事件超过调用方读缓冲(反代默认 32KB)就被截断。
// 普通聊天每条 delta 只有几十上百字节，永远踩不到；Codex 的 response.completed 事件
// 携带完整输出文本，回答一长就必然超标，所以表现为"短回答正常、长回答必断"。

func newStreamProcessorForTest(src io.ReadCloser) *StreamProcessor {
	waf := &WafEngine{}
	waf.InitRouting()
	waf.SensitiveDirectionMap = map[string]bool{} // 关闭出站敏感词，等价用户"关掉所有防护"
	ctx := innerbean.WafHttpContextData{
		HostCode: "test",
		Weblog:   &innerbean.WebLog{URL: "/v1/responses"},
	}
	return waf.createStreamProcessor(src, ctx, "test")
}

// chunkReader 按固定粒度吐数据，模拟 TCP 分片
type chunkReader struct {
	data  []byte
	pos   int
	chunk int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := min(min(c.chunk, len(p)), len(c.data)-c.pos)
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}
func (c *chunkReader) Close() error { return nil }

// eofWithDataReader 模拟 http body 的常见行为：最后一次 Read 同时返回数据和 io.EOF
type eofWithDataReader struct {
	data []byte
	done bool
}

func (e *eofWithDataReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.EOF
	}
	e.done = true
	return copy(p, e.data), io.EOF
}
func (e *eofWithDataReader) Close() error { return nil }

// readAllWithBuf 用固定大小的读缓冲抽干 reader，模拟反代 copyBuffer 的行为
func readAllWithBuf(r io.Reader, bufSize int) (string, error) {
	var out bytes.Buffer
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err == io.EOF {
			return out.String(), nil
		}
		if err != nil {
			return out.String(), err
		}
	}
}

const sseSample = "event: response.created\n" +
	"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n" +
	"\n" +
	"event: response.output_text.delta\n" +
	"data: {\"type\":\"response.output_text.delta\",\"delta\":\"哔哩\"}\n" +
	"\n" +
	"event: response.output_text.delta\n" +
	"data: {\"type\":\"response.output_text.delta\",\"delta\":\"哔哩，干杯!\"}\n" +
	"\n" +
	"event: response.completed\n" +
	"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\"}}\n" +
	"\n" +
	"data: [DONE]\n" +
	"\n"

// 无论上游怎么分片，输出必须与输入逐字节一致
func TestStreamProcessorSSEFidelityAcrossChunkSizes(t *testing.T) {
	for _, chunk := range []int{1, 3, 7, 16, 64, 4096} {
		sp := newStreamProcessorForTest(&chunkReader{data: []byte(sseSample), chunk: chunk})
		got, err := readAllWithBuf(sp, 32*1024)
		if err != nil {
			t.Fatalf("chunk=%d 读取失败: %v", chunk, err)
		}
		if got != sseSample {
			t.Errorf("chunk=%d 输出与输入不一致\ngot (%d):\n%q\nwant (%d):\n%q",
				chunk, len(got), got, len(sseSample), sseSample)
		}
	}
}

// #949/#954 回归：单条事件远超读缓冲时不得截断
func TestStreamProcessorLargeEventNotTruncated(t *testing.T) {
	// 512KB 的单条事件，对应 Codex 长回答时的 response.completed
	payload := strings.Repeat("A", 512*1024)
	big := "event: response.completed\ndata: {\"delta\":\"" + payload + "\"}\n\n"

	// 读缓冲刻意取小，放大截断效应；32KB 是反代 copyBuffer 的真实值
	for _, readBuf := range []int{512, 4096, 32 * 1024} {
		sp := newStreamProcessorForTest(&chunkReader{data: []byte(big), chunk: 8192})
		got, err := readAllWithBuf(sp, readBuf)
		if err != nil {
			t.Fatalf("readBuf=%d 读取失败: %v", readBuf, err)
		}
		if got != big {
			t.Errorf("readBuf=%d 单条大事件被截断：发出 %d 字节，读到 %d 字节",
				readBuf, len(big), len(got))
		}
	}
}

// 上游最后一段没有以换行结尾（连接中断/最后事件未闭合）时，残留数据不得丢
func TestStreamProcessorFlushesTailOnEOF(t *testing.T) {
	tail := "event: response.completed\ndata: {\"status\":\"completed\"}"
	sp := newStreamProcessorForTest(&eofWithDataReader{data: []byte(tail)})
	got, err := readAllWithBuf(sp, 32*1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != tail {
		t.Errorf("EOF 时残留数据丢失\ngot : %q\nwant: %q", got, tail)
	}
}

// CRLF 行尾的 SSE 不得被改写（早期实现会把 data 行重新拼装，吃掉行尾 \r）
func TestStreamProcessorPreservesCRLF(t *testing.T) {
	in := "event: ping\r\ndata: {\"a\":1}\r\n\r\ndata: [DONE]\r\n\r\n"
	sp := newStreamProcessorForTest(&chunkReader{data: []byte(in), chunk: 5})
	got, err := readAllWithBuf(sp, 32*1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Errorf("CRLF 被改写\ngot : %q\nwant: %q", got, in)
	}
}

// data 行里有意义的多余前导空格不得被吞掉
func TestStreamProcessorPreservesDataSpacing(t *testing.T) {
	in := "data:{\"compact\":true}\n\ndata:   三个空格\n\n"
	sp := newStreamProcessorForTest(&chunkReader{data: []byte(in), chunk: 4})
	got, err := readAllWithBuf(sp, 32*1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Errorf("data 行前导空格被改写\ngot : %q\nwant: %q", got, in)
	}
}

// 上游长时间不发换行时内存要有上限，且放行的字节仍然无损
func TestStreamProcessorCapsUnterminatedLine(t *testing.T) {
	in := strings.Repeat("B", maxStreamLineBytes+4096) // 全程没有 \n
	sp := newStreamProcessorForTest(&chunkReader{data: []byte(in), chunk: 64 * 1024})
	got, err := readAllWithBuf(sp, 32*1024)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Errorf("超长无换行内容被破坏：发出 %d 字节，读到 %d 字节", len(in), len(got))
	}
}
