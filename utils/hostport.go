package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"encoding/json"
	"strconv"
	"strings"
)

// 端口监听协议与 IP 版本的合法取值。
// IP 版本词汇与隧道 Tunnel.IpVersion 保持同一套（ipv4/ipv6/both）。
const (
	ListenProtoHTTP  = "http"
	ListenProtoHTTPS = "https"
	ListenIPVBoth    = "both"
	ListenIPV4       = "ipv4"
	ListenIPV6       = "ipv6"
)

// PortListenItem Hosts.PortListensJSON 的元素结构。
type PortListenItem struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Ipv   string `json:"ipv,omitempty"`
	Addr  string `json:"addr,omitempty"` // 预留字段：当前版本不生效，引擎读到会忽略并按通配监听
}

// HostListen 站点的一条监听配置（解析归一后的结果）。
// json 标签与 PortListenItem 对齐，前端把 resolved_listens 原样映射回端口行即可。
type HostListen struct {
	Port      int    `json:"port"`
	Protocol  string `json:"proto"` // http | https
	IPVersion string `json:"ipv"`   // both | ipv4 | ipv6
	Addr      string `json:"addr"`  // 恒为空，预留
	IsMain    bool   `json:"is_main"`
	// Implied 表示 AutoJumpHTTPS 隐式补出的 80 监听：只负责起监听，
	// 不注册域名路由（路由由 LoadHost 既有的 AutoJumpHTTPS 分支处理）。
	Implied bool `json:"implied"`
}

// Network 返回应传给 net.Listen 的 network 参数。
func (l HostListen) Network() string {
	switch l.IPVersion {
	case ListenIPV4:
		return "tcp4"
	case ListenIPV6:
		return "tcp6"
	default:
		return "tcp"
	}
}

// UDPNetwork 返回 HTTP/3(QUIC) 应使用的 UDP network 参数，与 TCP 侧保持同一 IP 版本。
func (l HostListen) UDPNetwork() string {
	switch l.IPVersion {
	case ListenIPV4:
		return "udp4"
	case ListenIPV6:
		return "udp6"
	default:
		return "udp"
	}
}

// ListenAddr 返回监听地址字符串（显式写出通配地址，便于日志排障）。
func (l HostListen) ListenAddr() string {
	switch l.IPVersion {
	case ListenIPV4:
		return "0.0.0.0:" + strconv.Itoa(l.Port)
	case ListenIPV6:
		return "[::]:" + strconv.Itoa(l.Port)
	default:
		return ":" + strconv.Itoa(l.Port)
	}
}

// NetworkForIPVersion 与 UDPNetworkForIPVersion 供只有 IPVersion 字符串的调用方（如 ServerRunTime）使用。
func NetworkForIPVersion(ipv string) string {
	return HostListen{IPVersion: ipv}.Network()
}

func UDPNetworkForIPVersion(ipv string) string {
	return HostListen{IPVersion: ipv}.UDPNetwork()
}

// ResolveHostListens 站点「端口→协议→IP版本」的唯一真源。
// PortListensJSON 非空则以显式声明为准；为空则按老规则派生，保证存量站点行为不变。
// 其它任何地方不得自行解析 PortListensJSON / BindMorePort。
func ResolveHostListens(h model.Hosts) []HostListen {
	if h.GLOBAL_HOST == 1 {
		return nil
	}
	raw := strings.TrimSpace(h.PortListensJSON)
	if raw == "" {
		return legacyDeriveListens(h)
	}
	var items []PortListenItem
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		// 整体解析失败必须回落派生：一段坏 JSON 不能让站点失联
		zlog.Warn("站点端口监听表JSON解析失败，回落按老规则派生", "host", h.Host, "code", h.Code, "error", err.Error())
		return legacyDeriveListens(h)
	}

	out := make([]HostListen, 0, len(items)+1)
	seen := map[int]int{} // port -> out 下标
	for _, it := range items {
		if it.Port < 1 || it.Port > 65535 {
			zlog.Warn("站点端口监听表含非法端口，已忽略该条", "host", h.Host, "port", it.Port)
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(it.Proto))
		if proto != ListenProtoHTTP && proto != ListenProtoHTTPS {
			zlog.Warn("站点端口监听表含非法协议，已忽略该条", "host", h.Host, "port", it.Port, "proto", it.Proto)
			continue
		}
		ipv := strings.ToLower(strings.TrimSpace(it.Ipv))
		if ipv == "" {
			ipv = ListenIPVBoth
		}
		if ipv != ListenIPVBoth && ipv != ListenIPV4 && ipv != ListenIPV6 {
			zlog.Warn("站点端口监听表含非法IP版本，按both处理", "host", h.Host, "port", it.Port, "ipv", it.Ipv)
			ipv = ListenIPVBoth
		}
		if strings.TrimSpace(it.Addr) != "" {
			zlog.Warn("站点端口监听表的addr为预留字段当前版本不生效，按通配地址监听", "host", h.Host, "port", it.Port, "addr", it.Addr)
		}
		l := HostListen{Port: it.Port, Protocol: proto, IPVersion: ipv, IsMain: it.Port == h.Port}
		if idx, ok := seen[it.Port]; ok {
			zlog.Warn("站点端口监听表含重复端口，后者覆盖前者", "host", h.Host, "port", it.Port)
			out[idx] = l
			continue
		}
		seen[it.Port] = len(out)
		out = append(out, l)
	}

	if len(out) == 0 {
		zlog.Warn("站点端口监听表无任何有效条目，回落按老规则派生", "host", h.Host, "code", h.Code)
		return legacyDeriveListens(h)
	}

	// 主端口必须在表内：缺失则按老规则补一条，防止脏数据导致站点整个失联
	if _, ok := seen[h.Port]; !ok && h.Port >= 1 && h.Port <= 65535 {
		zlog.Warn("站点端口监听表缺少主端口，已按老规则补齐", "host", h.Host, "port", h.Port)
		main := HostListen{Port: h.Port, Protocol: legacyMainProto(h), IPVersion: ListenIPVBoth, IsMain: true}
		out = append([]HostListen{main}, out...)
		reindex(seen, out)
	}

	// AutoJumpHTTPS：表内未含 80 才隐式补；已显式声明 80 则以声明为准不覆盖
	if h.AutoJumpHTTPS == 1 {
		if _, ok := seen[80]; !ok {
			out = append(out, HostListen{Port: 80, Protocol: ListenProtoHTTP, IPVersion: ListenIPVBoth, Implied: true})
		}
	}

	moveMainFirst(out)
	return out
}

// legacyDeriveListens 空表派生：逐条复刻 PortListensJSON 出现之前的行为（含 80+Ssl=1→https），
// 保证存量站点升级后现象逐字节一致。规则对应的老代码位置见设计文档。
func legacyDeriveListens(h model.Hosts) []HostListen {
	var out []HostListen
	seen := map[int]bool{}
	if h.Port >= 1 && h.Port <= 65535 {
		out = append(out, HostListen{Port: h.Port, Protocol: legacyMainProto(h), IPVersion: ListenIPVBoth, IsMain: true})
		seen[h.Port] = true
	}
	// 副端口必须先于 AutoJump 隐式 80：BindMorePort 里显式写了 80 的站点，
	// 老代码会把它计入路由副端口（副域名:80 也注册路由）；若先补 implied 80，
	// 这个 80 会被误标 Implied 而丢掉副域名:80 路由，且前端保存时会把它从 bind_more_port 抹掉
	if h.BindMorePort != "" {
		for _, portStr := range strings.Split(h.BindMorePort, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil || port < 1 || port > 65535 || seen[port] {
				continue
			}
			proto := ListenProtoHTTP
			if port == 443 || (h.Ssl == 1 && port != 80) {
				proto = ListenProtoHTTPS
			}
			out = append(out, HostListen{Port: port, Protocol: proto, IPVersion: ListenIPVBoth})
			seen[port] = true
		}
	}
	if h.AutoJumpHTTPS == 1 && !seen[80] {
		out = append(out, HostListen{Port: 80, Protocol: ListenProtoHTTP, IPVersion: ListenIPVBoth, Implied: true})
		seen[80] = true
	}
	return out
}

func legacyMainProto(h model.Hosts) string {
	if h.Ssl == 1 {
		return ListenProtoHTTPS
	}
	return ListenProtoHTTP
}

func reindex(seen map[int]int, out []HostListen) {
	for i := range out {
		seen[out[i].Port] = i
	}
}

func moveMainFirst(out []HostListen) {
	for i := range out {
		if out[i].IsMain {
			if i != 0 {
				main := out[i]
				copy(out[1:i+1], out[0:i])
				out[0] = main
			}
			return
		}
	}
}

// HostListenPorts 返回站点全部监听端口（含隐式 80），供端口引用计数等场景使用。
func HostListenPorts(h model.Hosts) []int {
	listens := ResolveHostListens(h)
	ports := make([]int, 0, len(listens))
	for _, l := range listens {
		ports = append(ports, l.Port)
	}
	return ports
}

// HostRoutedExtraPorts 返回需要注册域名路由的副端口（不含主端口、不含隐式 80），
// 与老代码里 BindMorePort 解析出的 ports 列表语义一致。
func HostRoutedExtraPorts(h model.Hosts) []int {
	listens := ResolveHostListens(h)
	ports := make([]int, 0, len(listens))
	for _, l := range listens {
		if l.IsMain || l.Implied {
			continue
		}
		ports = append(ports, l.Port)
	}
	return ports
}

// HostMainProtocol 返回主端口的监听协议（找不到主端口时按老规则派生），
// 供「回源 origin / 防篡改基线 scheme」等需要判断站点对外协议的场景使用。
func HostMainProtocol(h model.Hosts) string {
	for _, l := range ResolveHostListens(h) {
		if l.IsMain {
			return l.Protocol
		}
	}
	return legacyMainProto(h)
}
