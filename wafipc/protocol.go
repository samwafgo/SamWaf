// Package wafipc 定义 Supervisor 与 Worker 之间的控制通道协议与传输。
//
// 传输选型：采用 127.0.0.1 环回 TCP + token 鉴权。
//   - 跨平台一致（含 Win7，AF_UNIX 仅 Win10+ 不可用、命名管道需额外依赖）；
//   - 可重连：Worker 与 Supervisor 断开后可重新连接（支撑 Supervisor 自升级后的“再认领”）；
//   - 仅监听 127.0.0.1，并以随机 token 鉴权，限制本机攻击面。
//
// 消息为按行分隔的 JSON（json.Encoder/Decoder 流式读写），便于调试与版本演进。
package wafipc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"time"
)

// ProtoVersion 控制协议版本。老 Supervisor 管新 Worker 时若版本不兼容，
// Supervisor 应放弃滚动升级并回退到全量重启（见设计文档 §4.4）。
const ProtoVersion = 1

// 消息类型。
const (
	// Worker → Supervisor
	MsgHello          = "HELLO"           // 注册：携带 pid/version/proto_ver/token
	MsgReady          = "READY"           // 端口就绪自检通过，可承接流量
	MsgHeartbeat      = "HEARTBEAT"       // 心跳：携带当前连接数
	MsgDraining       = "DRAINING"        // 排空进度：剩余连接数
	MsgGone           = "GONE"            // 已完成排空，即将退出
	MsgRequestUpgrade = "REQUEST_UPGRADE" // 请求 Supervisor 发起滚动升级

	// 运维/测试 → Supervisor（经 token 鉴权的外部连接，无需注册为 Worker）
	MsgTriggerUpgrade = "TRIGGER_UPGRADE" // 手动触发一次滚动重启(零停机换 Worker)，用于测试或运维 reload
	MsgAck            = "ACK"             // Supervisor 对 TRIGGER_UPGRADE 的应答

	// Supervisor → Worker
	MsgDrain    = "DRAIN"    // 令其优雅排空并退出（携带 timeout 秒）
	MsgShutdown = "SHUTDOWN" // 令其立即优雅停止退出
	MsgActivate = "ACTIVATE" // 旧 Worker 已退出，令新 Worker 接管独占型单例(应用/隧道/cron)
	MsgPing     = "PING"
	MsgPong     = "PONG"
)

// Message 是控制通道上的统一消息体。
type Message struct {
	Type     string `json:"type"`
	PID      int    `json:"pid,omitempty"`
	Version  string `json:"version,omitempty"`
	ProtoVer int    `json:"proto_ver,omitempty"`
	Token    string `json:"token,omitempty"`

	Active    int64 `json:"active,omitempty"`    // HEARTBEAT：在途/打开的连接数
	Remaining int64 `json:"remaining,omitempty"` // DRAINING：剩余连接数
	Timeout   int   `json:"timeout,omitempty"`   // DRAIN：排空超时(秒)

	Path string `json:"path,omitempty"` // REQUEST_UPGRADE：新二进制路径(可选)
	Err  string `json:"err,omitempty"`
}

// Conn 包装一条控制连接，提供 JSON 消息收发。
type Conn struct {
	raw net.Conn
	enc *json.Encoder
	dec *json.Decoder
}

// NewConn 基于已建立的 net.Conn 创建控制连接。
func NewConn(c net.Conn) *Conn {
	return &Conn{raw: c, enc: json.NewEncoder(c), dec: json.NewDecoder(c)}
}

// Send 发送一条消息（线程不安全，调用方需自行串行化写入）。
func (c *Conn) Send(m Message) error { return c.enc.Encode(&m) }

// Recv 阻塞读取一条消息。
func (c *Conn) Recv() (Message, error) {
	var m Message
	err := c.dec.Decode(&m)
	return m, err
}

// Close 关闭底层连接。
func (c *Conn) Close() error { return c.raw.Close() }

// SetDeadline 设置底层连接读写截止时间。
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// RemoteAddr 返回对端地址。
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// Listen 在 127.0.0.1:port 上监听控制通道。port 传 0 由系统分配。
func Listen(port int) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
}

// Dial 连接到 Supervisor 的控制通道地址（形如 "127.0.0.1:port"）。
func Dial(addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewConn(c), nil
}

// GenToken 生成一个随机鉴权 token。
func GenToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "samwaf-fallback-token"
	}
	return hex.EncodeToString(b)
}
