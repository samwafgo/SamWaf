package wafhostguard

import (
	"encoding/xml"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Windows 事件日志解析。与 sshd 解析器一样是纯逻辑、无 build tag，
// 可以在 Linux/macOS 上跑单测。
//
// 涉及两个频道：
//   - Security 的 4625：登录失败。带用户名、登录类型，但**源 IP 可能是 "-"**。
//   - RemoteDesktopServices-RdpCoreTS/Operational 的 131/140：RDP 连接层事件，
//     带真实客户端 IP，用来补 4625 缺失的来源。

// winEvent 只取需要的字段。EventData/UserData 的结构在不同 Windows 版本里差异很大，
// 所以 UserData 一律按原始文本处理，用正则抓 IP，而不是硬编码字段名——
// 硬编码的后果是换个系统版本就静默失效。
type winEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID       int    `xml:"EventID"`
		Channel       string `xml:"Channel"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
}

// winIPRe 从任意文本里抓形似 IP 的片段，抓完交 net.ParseIP 严格校验
var winIPRe = regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b|\[?([0-9a-fA-F]*:[0-9a-fA-F:.]+)\]?`)

// Parse4625 解析安全日志 4625(登录失败)。
//
// needResolve=true 表示这条事件的 IpAddress 不可用("-"、空、或环回)，
// 必须靠 RdpCoreTS 的 131/140 事件按时间关联补齐；补不到就只能丢弃。
func Parse4625(xmlStr string, now time.Time) (ev LoginFailEvent, needResolve bool, ok bool) {
	var e winEvent
	if err := xml.Unmarshal([]byte(xmlStr), &e); err != nil {
		return LoginFailEvent{}, false, false
	}
	if e.System.EventID != 4625 {
		return LoginFailEvent{}, false, false
	}

	data := make(map[string]string, len(e.EventData.Data))
	for _, d := range e.EventData.Data {
		data[d.Name] = strings.TrimSpace(d.Value)
	}

	logonType := data["LogonType"]
	// 只关心远程登录：10=RemoteInteractive(RDP)、3=Network(SMB/IPC$ 等)。
	// 2(本地交互)、4(批处理)、5(服务)这些是本机行为，封了毫无意义还可能误伤。
	if logonType != "10" && logonType != "3" {
		return LoginFailEvent{}, false, false
	}

	at := now
	if t, err := time.Parse(time.RFC3339, e.System.TimeCreated.SystemTime); err == nil {
		at = t
	}

	ev = LoginFailEvent{
		Source:    SourceRDP,
		User:      data["TargetUserName"],
		Kind:      FailRdpLogon,
		LogonType: logonType,
		Raw:       TruncRaw(summarize4625(data, e.System.EventRecordID)),
		At:        at,
	}
	if p := data["IpPort"]; p != "" {
		ev.Port, _ = strconv.Atoi(p)
	}

	ip := data["IpAddress"]
	if !usableRemoteIP(ip) {
		return ev, true, true
	}
	ev.IP = normalizeIP(ip)
	return ev, false, true
}

// ParseRdpCoreTSIP 从 RdpCoreTS 131/140 事件里抓客户端 IP。
//
//	140：无法从客户端 <IP> 建立连接(认证失败/协议错误)
//	131：服务器接受了来自 <IP:port> 的新 TCP 连接
//
// 字段名随版本变化(IPString / ClientIP / Param1 ...)，所以直接扫 UserData 的
// 全部文本找第一个合法 IP，不依赖具体字段名。
func ParseRdpCoreTSIP(xmlStr string, now time.Time) (ip string, at time.Time, ok bool) {
	var e winEvent
	if err := xml.Unmarshal([]byte(xmlStr), &e); err != nil {
		return "", time.Time{}, false
	}
	if e.System.EventID != 131 && e.System.EventID != 140 {
		return "", time.Time{}, false
	}

	at = now
	if t, err := time.Parse(time.RFC3339, e.System.TimeCreated.SystemTime); err == nil {
		at = t
	}

	if found := findFirstIP(e.UserData.Inner); found != "" {
		return found, at, true
	}
	// 少数版本把内容放在 EventData 里
	for _, d := range e.EventData.Data {
		if found := findFirstIP(d.Value); found != "" {
			return found, at, true
		}
	}
	return "", at, false
}

// findFirstIP 从文本中找出第一个可用的远端 IP
func findFirstIP(s string) string {
	if s == "" {
		return ""
	}
	for _, m := range winIPRe.FindAllStringSubmatch(s, -1) {
		for _, candidate := range m[1:] {
			candidate = strings.Trim(strings.TrimSpace(candidate), "[]")
			if candidate == "" {
				continue
			}
			if !usableRemoteIP(candidate) {
				continue
			}
			return normalizeIP(candidate)
		}
	}
	return ""
}

// usableRemoteIP 判断这个字符串是不是一个能拿来封禁的远端地址。
//
// 排除掉 "-"(Windows 表示"未知")、环回、未指定地址。这些都不是攻击者，
// 封了只会伤到自己。**绝不做任何猜测性兜底**——宁可漏封一次，不可错封一个。
func usableRemoteIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return false
	}
	// 131 事件的 ClientIP 形如 1.2.3.4:51234 或 [::1]:5555
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return false
	}
	return true
}

// normalizeIP 去掉端口与方括号，返回规范化的 IP 文本
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// summarize4625 生成一行可读摘要入库，比塞整段 XML 有用得多
func summarize4625(data map[string]string, recordID uint64) string {
	var b strings.Builder
	b.WriteString("EventID=4625")
	if recordID > 0 {
		b.WriteString(" RecordID=")
		b.WriteString(strconv.FormatUint(recordID, 10))
	}
	for _, k := range []string{"TargetUserName", "TargetDomainName", "LogonType", "IpAddress", "IpPort", "WorkstationName", "Status", "SubStatus", "FailureReason"} {
		if v := data[k]; v != "" {
			b.WriteString(" ")
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
		}
	}
	return b.String()
}
