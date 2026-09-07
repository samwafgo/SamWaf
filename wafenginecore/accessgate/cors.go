package accessgate

import (
	"net/http"
	"strconv"
	"strings"
)

// cors.go 是「统一访问认证」的跨源策略判定与响应头构造。
//
// 只在两个地方被用到，都在**认证通过之前**：
//   - CORS 预检代答（WAF 自己回 204，请求不落到后端）
//   - 未认证响应（401/302）补头，让跨源前端能读到干净的 401 而不是一句 CORS 错
//
// 认证通过后放行的响应一律不补头：后端自己会回，WAF 再补一份会出现两个
// Access-Control-Allow-Origin，浏览器直接判失败。

const (
	corsDefaultMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	corsDefaultMaxAge  = 600
	corsMaxAgeCap      = 7200

	// 白名单是热路径上的 O(n) 遍历，条数与长度都要封顶，避免被配置成 CPU 放大器
	corsMaxOrigins   = 64
	corsMaxOriginLen = 512
	// 回显给客户端的头值上限
	corsMaxHeaderLen = 1024
)

// CORSPolicy 是「这个站点此刻的跨源策略」，由站点级按字段覆盖全局后得到。
// AllowOrigins 为空即视为功能未启用——默认关，存量用户零影响。
type CORSPolicy struct {
	AllowOrigins []string // 已小写、已校验、已去重
	AllowMethods string
	AllowHeaders string // 空 = 回显请求的 Access-Control-Request-Headers
	MaxAge       int
}

// Enabled 未配置任何允许的 Origin 就是没开这个功能。
func (p CORSPolicy) Enabled() bool { return len(p.AllowOrigins) > 0 }

// BuildAllowOrigins 把用户填的多行文本解析成允许的 Origin 清单。
//
// 非法条目直接丢弃而不报错：这份配置在热路径上使用，宁可少放行一条，
// 也不能因为一行写歪就让整站跨源全挂或全开。
func BuildAllowOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	replaced := strings.NewReplacer("\r\n", "\n", "\r", "\n", ",", "\n").Replace(raw)
	var out []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(replaced, "\n") {
		o := normalizeOrigin(line)
		if o == "" {
			continue
		}
		if _, dup := seen[o]; dup {
			continue
		}
		seen[o] = struct{}{}
		out = append(out, o)
		if len(out) >= corsMaxOrigins {
			break
		}
	}
	return out
}

// normalizeOrigin 校验并归一化单个 Origin，非法返回空串。
//
// 显式拒绝两类值：
//   - "null"：来自 sandbox iframe / data: / file://，允许它等于对任意攻击页面开放
//   - "*"：规范禁止「带凭据 + ACAO 通配」，不该由我们产出这种组合
//
// 端口一律保留。抹掉端口就等于让 :7013 的白名单顺手放行 :9999 ——
// 而端口正是这次事故的核心边界。
func normalizeOrigin(item string) string {
	o := strings.ToLower(strings.TrimSpace(item))
	if o == "" || o == "*" || o == "null" {
		return ""
	}
	if len(o) > corsMaxOriginLen {
		return ""
	}
	if strings.ContainsAny(o, "\r\n\t ") {
		return ""
	}
	var rest string
	switch {
	case strings.HasPrefix(o, "http://"):
		rest = o[len("http://"):]
	case strings.HasPrefix(o, "https://"):
		rest = o[len("https://"):]
	default:
		return ""
	}
	// Origin 按定义只有 scheme://host[:port]，出现路径/查询/片段说明用户填错了。
	// 丢弃比「猜他想要什么」安全：猜错的方向通常是放宽。
	if rest == "" || strings.ContainsAny(rest, "/?#\\") {
		return ""
	}
	return o
}

// RequestOrigin 取请求的 Origin；出现零个或多个 Origin 头都判为无效。
//
// 多头必须拒绝而不是取第一个：前置代理与本网关若各取一个，
// 判定所依据的值就和实际生效的值不是同一个，那本身就是绕过。
func RequestOrigin(h http.Header) string {
	v := h["Origin"]
	if len(v) != 1 {
		return ""
	}
	return strings.TrimSpace(v[0])
}

// MatchOrigin 判断 Origin 是否在白名单里，命中返回**白名单里的那一条**。
//
// 两个刻意的设计：
//   - 整串精确比对。任何前缀/后缀/包含式匹配都能被
//     http://oa.x:7013.evil.com 或 http://evil.com/?http://oa.x:7013 命中。
//   - 返回白名单侧的值，而不是把请求头原样回显。比对与输出只要来自两个来源，
//     任何归一化差异都会长成绕过；这里从结构上杜绝。
func MatchOrigin(origin string, allow []string) (string, bool) {
	if origin == "" || len(allow) == 0 {
		return "", false
	}
	o := strings.ToLower(strings.TrimSpace(origin))
	if o == "" || o == "null" || o == "*" {
		return "", false
	}
	for _, item := range allow {
		if item == o {
			return item, true
		}
	}
	return "", false
}

// IsPreflight 判断是不是 CORS 预检。三个条件缺一不可 ——
// 少判一个就会把普通的 OPTIONS 请求也当成预检代答掉，而后者可能是业务接口。
func IsPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		RequestOrigin(r.Header) != "" &&
		strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")) != ""
}

// WriteCORSHeaders 给未认证响应补 CORS 头。
//
// allowedOrigin 必须是 MatchOrigin 的返回值（白名单侧的那一条）。
//
// Access-Control-Allow-Credentials 固定 true 且不给开关：带凭据是这个功能存在的
// 唯一理由，而规范禁止带凭据时 ACAO 为 *，所以必须回显具体 Origin，
// 也就必须有白名单 —— 两件事绑死，给开关只会造出无意义的组合。
//
// Vary 用 Add 不用 Set：这条响应可能已经带了别的 Vary，覆盖掉会让缓存串味。
func WriteCORSHeaders(w http.ResponseWriter, allowedOrigin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", allowedOrigin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "X-SamWaf-Access")
	h.Add("Vary", "Origin")
}

// WritePreflightHeaders 构造预检代答的响应头（不含状态码，由调用方写 204）。
func WritePreflightHeaders(w http.ResponseWriter, r *http.Request, allowedOrigin string, p CORSPolicy) {
	WriteCORSHeaders(w, allowedOrigin)
	h := w.Header()

	methods := p.AllowMethods
	if methods == "" {
		methods = corsDefaultMethods
	}
	h.Set("Access-Control-Allow-Methods", methods)

	allowHeaders := p.AllowHeaders
	if allowHeaders == "" {
		// 用户没指定就回显请求想用的头。该值完全由客户端控制，
		// 必须过滤控制字符并封顶长度：Go 的 ResponseWriter 虽会把 CR/LF 换成空格、
		// 不至于头分割，但不该把边界押在运行时兜底上，超长值本身也是放大器。
		allowHeaders = SanitizeHeaderValue(r.Header.Get("Access-Control-Request-Headers"))
	}
	if allowHeaders != "" {
		h.Set("Access-Control-Allow-Headers", allowHeaders)
	}

	maxAge := p.MaxAge
	if maxAge <= 0 {
		maxAge = corsDefaultMaxAge
	}
	if maxAge > corsMaxAgeCap {
		maxAge = corsMaxAgeCap
	}
	h.Set("Access-Control-Max-Age", strconv.Itoa(maxAge))
	// 回显了请求头清单，缓存就必须按它分桶
	h.Add("Vary", "Access-Control-Request-Headers")
}

// AddVaryOrigin 只加 Vary 不加别的。
//
// 未命中白名单的响应同样要声明「本响应随 Origin 变化」，否则共享缓存
// 可能把带 CORS 头的那份和不带的那份混着发。命中与不命中都加，行为才对称。
func AddVaryOrigin(w http.ResponseWriter) {
	w.Header().Add("Vary", "Origin")
}

// SanitizeHeaderValue 丢掉控制字符并按上限截断。
// 两处用到：回显客户端可控的 Access-Control-Request-Headers，
// 以及管理端填进来的 methods/headers 配置值。
func SanitizeHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) > corsMaxHeaderLen {
		v = v[:corsMaxHeaderLen]
	}
	var b strings.Builder
	b.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// ResolveCORSPolicy 站点级按字段覆盖全局。
//
// 按字段而不是整体覆盖，是为了让用户只改 Origin 清单就能生效，
// 继续沿用全局配好的方法/头/缓存时长。
func ResolveCORSPolicy(hostOrigins, hostMethods, hostHeaders string, hostMaxAge int, g CORSPolicy) CORSPolicy {
	p := g
	switch strings.TrimSpace(hostOrigins) {
	case "":
		// 沿用全局
	case "-":
		// 显式关闭。没有这个哨兵的话，为某一个站点配的 Origin 会在所有继承全局的
		// 站点上一并生效，而站点侧没有任何办法把它关掉。
		p.AllowOrigins = nil
	default:
		// 站点填了就以站点为准，哪怕全部条目非法解析成空也不回落全局：
		// 用户的意图是「这个站点单独管」，回落全局等于悄悄放宽。
		p.AllowOrigins = BuildAllowOrigins(hostOrigins)
	}
	if m := SanitizeHeaderValue(hostMethods); m != "" {
		p.AllowMethods = m
	}
	if hd := SanitizeHeaderValue(hostHeaders); hd != "" {
		p.AllowHeaders = hd
	}
	if hostMaxAge > 0 {
		p.MaxAge = hostMaxAge
	}
	return p
}
