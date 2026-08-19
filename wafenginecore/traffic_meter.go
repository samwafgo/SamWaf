package wafenginecore

import (
	"SamWaf/global"
	"bufio"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// 站点流量计量：在引擎最外层直接量「真实写给客户端 / 真实从客户端读到」的字节数，
// 与「是否记录访问日志」彻底解耦（issue #930）。
//
// 为什么不能继续靠访问日志累加：
//   - 静态资源（图片/CSS/JS/音视频，以及任何带 Accept-Ranges 的响应）在 modifyResponse
//     里整条日志都不入队，字节自然全丢；
//   - chunked / 流式响应的 Content-Length 是 -1，日志字段只能记 0；
//   - 用户把「日志记录类型」调成「只记异常」后，正常流量的账会整体消失。
//
// 包装层必须把这些接口透传下去，否则是回归事故：
//   - http.Hijacker  —— wafproxy/reverseproxy.go 里协议升级强制要求，不实现 WebSocket 直接 500
//   - http.Flusher   —— 不实现 SSE / 流式响应会被缓冲住
//   - io.ReaderFrom  —— 保住 sendfile/TransmitFile 快路径（http.ServeFile 静态伺服走这条）
//   - http.Pusher / http.CloseNotifier —— reverseproxy 会做类型断言
//   - Unwrap         —— http.ResponseController 靠它找底层能力

// trafficMeter 单次请求的字节账本。
// 用 atomic：WebSocket 劫持后由两个 copy 协程并发读写同一条连接。
type trafficMeter struct {
	hostCode string
	host     string
	day      int   // 请求发生时刻所属的天，不是落库时刻
	hourTime int64 // 请求发生时刻所属的整点
	in       atomic.Int64
	out      atomic.Int64
}

func (m *trafficMeter) addIn(n int64) {
	if n > 0 {
		m.in.Add(n)
	}
}

func (m *trafficMeter) addOut(n int64) {
	if n > 0 {
		m.out.Add(n)
	}
}

// settle 结账：把账本清零并交给累加器。
// 用 Swap 而不是 Load，保证重复调用不会重复计数（劫持连接的迟到字节也只算一次）。
func (m *trafficMeter) settle() {
	in := m.in.Swap(0)
	out := m.out.Swap(0)
	global.AddTraffic(m.hostCode, m.host, m.day, m.hourTime, in, out)
}

// countingResponseWriter 计出站字节
type countingResponseWriter struct {
	http.ResponseWriter
	m trafficMeter // 值内嵌，每请求少一次堆分配
}

func (c *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.m.addOut(int64(n))
	return n, err
}

// Unwrap 供 http.ResponseController 找到底层 ResponseWriter（SetReadDeadline 等）
func (c *countingResponseWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}

func (c *countingResponseWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := c.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// CloseNotify 透传。底层不支持时返回一个永不触发的通道：
// 调用方（reverseproxy）只在请求 ctx 无 Done 通道时才会走到这里，
// 而真实服务器请求的 ctx 一定是可取消的，因此实际不会命中。
func (c *countingResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := c.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return make(chan bool, 1)
}

// Hijack 透传，并把劫持后的连接也纳入计量（WebSocket 隧道字节全靠这条）
func (c *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := c.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	cc := &countingConn{Conn: conn, m: &c.m}
	if brw == nil {
		return cc, nil, nil
	}

	// http server 已经预读进 bufio 但业务还没消费的字节：它们是从原始 conn 读出来的，
	// 这里补计一次入站，之后的读走 countingConn。
	// 必须用 LimitReader 把旧 Reader 截断到已缓冲长度，否则读空缓冲后会继续
	// 从未计量的原始 conn 上阻塞读取。
	var src io.Reader = cc
	if buffered := brw.Reader.Buffered(); buffered > 0 {
		c.m.addIn(int64(buffered))
		src = io.MultiReader(io.LimitReader(brw.Reader, int64(buffered)), cc)
	}
	// 写侧：net/http 在 Hijack 时给的是一个全新的空 bufio.Writer，没有待刷字节，
	// 直接换成写向 countingConn 的新 Writer 是安全的。
	return cc, bufio.NewReadWriter(bufio.NewReader(src), bufio.NewWriter(cc)), nil
}

// writerOnly 屏蔽 ReadFrom，防止 io.Copy 递归回自己
type writerOnly struct{ io.Writer }

// ReadFrom 委托给底层，保住 sendfile/TransmitFile 快路径；底层不支持才退回逐块拷贝
func (c *countingResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		c.m.addOut(n)
		return n, err
	}
	n, err := io.Copy(writerOnly{c.ResponseWriter}, src)
	c.m.addOut(n)
	return n, err
}

// countingBody 计入站字节（chunked 上传也天然正确，因为量的是真实读出来的量）
type countingBody struct {
	io.ReadCloser
	m *trafficMeter
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.m.addIn(int64(n))
	return n, err
}

// countingConn 劫持后的连接双向计量
type countingConn struct {
	net.Conn
	m *trafficMeter
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.m.addIn(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.m.addOut(int64(n))
	return n, err
}

// NetConn 暴露底层连接，供需要具体连接类型的调用方解包
func (c *countingConn) NetConn() net.Conn { return c.Conn }

// attachTrafficMeter 给一次请求挂上计量，返回包装后的 ResponseWriter 与结账函数。
// 分桶时间在这里取一次（= 请求发生时刻），绝不能等到落库时再算。
func attachTrafficMeter(w http.ResponseWriter, r *http.Request, hostCode, host string) (http.ResponseWriter, func()) {
	day, hourTime := global.TrafficBucketOf(time.Now())
	cw := &countingResponseWriter{
		ResponseWriter: w,
		m: trafficMeter{
			hostCode: hostCode,
			host:     host,
			day:      day,
			hourTime: hourTime,
		},
	}
	if r != nil && r.Body != nil && r.Body != http.NoBody {
		r.Body = &countingBody{ReadCloser: r.Body, m: &cw.m}
	}
	return cw, cw.m.settle
}
