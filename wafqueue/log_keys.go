package wafqueue

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// 窄行上的三个分析键（M5 汇总与 facet 的数据地基），落库这一步行级算好。
// 归一化规则一改，历史数据与新数据就不可比（汇总失真），所以规则由 log_keys_test.go 钉死：
// 改这里的判定必须连测试一起改，并在提交记录里说明。

// ActorKey 访问者身份：只有 IP 可用。
// 注意不能拿 GUEST_IDENTIFICATION 当身份——它是引擎写的分类标签
// （正常访客/可疑用户/bot 名/触发敏感词…），全站只有几个取值，
// 当键会把所有正常访客聚成一个 actor。分类聚合直接查窄行的 guest_id_entification 列。
func ActorKey(ip string) string {
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

// UaHash UA 指纹：聚合「同一个访问者用过多少种 UA」用，不存原文。
func UaHash(ua string) string {
	if ua == "" {
		return ""
	}
	sum := sha1.Sum([]byte(ua))
	return hex.EncodeToString(sum[:])[:16]
}

// PayloadHash 手法指纹：规则 + 命中内容（body hash）的归一化哈希。
// 「同 hash 出现在多个 IP 上」= 不同来源在用同一手法打。
func PayloadHash(rule, bodyHash string) string {
	if rule == "" && bodyHash == "" {
		return ""
	}
	sum := sha1.Sum([]byte(rule + "|" + bodyHash))
	return hex.EncodeToString(sum[:])[:16]
}

// pathNormMaxLen 与窄行表 path_norm 列宽一致。
const pathNormMaxLen = 512

// NormalizePath 把 URL 路径模板化，否则 /item/123456 每个都是新路径，汇总会被爬虫扫目录打爆。
// 规则（改动必须同步守护用例）：
//   - 去掉 query 与 fragment，只留路径
//   - 纯数字段 → {n}；UUID（8-4-4-4-12）→ {id}；长度≥16 的纯 hex 段 → {h}
//   - 末段保留扩展名：/img/12345.jpg → /img/{n}.jpg
//   - 超过 32 字符的段（多半是 token/长随机串）→ {s}
func NormalizePath(rawURL string) string {
	path := rawURL
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		ext := ""
		base := seg
		if i == len(segs)-1 { // 末段保留扩展名
			if dot := strings.LastIndexByte(seg, '.'); dot > 0 && len(seg)-dot <= 10 {
				ext = seg[dot:]
				base = seg[:dot]
			}
		}
		segs[i] = normSegment(base) + ext
	}
	out := strings.Join(segs, "/")
	if len(out) > pathNormMaxLen {
		out = out[:pathNormMaxLen]
	}
	return out
}

func normSegment(seg string) string {
	if seg == "" {
		return seg
	}
	if isAllDigits(seg) {
		return "{n}"
	}
	if isUUID(seg) {
		return "{id}"
	}
	if len(seg) >= 16 && isHex(seg) {
		return "{h}"
	}
	if len(seg) > 32 {
		return "{s}"
	}
	return seg
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// isUUID 形如 8-4-4-4-12 的 hex 段
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// AnalysisRowsFromLogs 把一批日志投影成分析层要的最小行，三个键就地算好。
// 键在这边算是刻意的：waftask 不能反向 import wafqueue（日志队列正在调它，会成环），
// 而键又必须和落进 access_log / security_event 的列出自同一套函数，否则汇总口径会和明细漂移。
//
// 不看档位：明细写多少由 tierForStore 决定，汇总永远吃全量请求流。
func AnalysisRowsFromLogs(logs []*innerbean.WebLog) []model.LogAnalysisRow {
	rows := make([]model.LogAnalysisRow, 0, len(logs))
	for _, lg := range logs {
		if lg == nil {
			continue
		}
		rows = append(rows, model.LogAnalysisRow{
			HostCode:   lg.HOST_CODE,
			Day:        lg.Day,
			ActorKey:   ActorKey(lg.SRC_IP),
			PathNorm:   NormalizePath(lg.URL),
			UaHash:     UaHash(lg.USER_AGENT),
			Rule:       lg.RULE,
			Action:     lg.ACTION,
			StatusCode: lg.STATUS_CODE,
		})
	}
	return rows
}
