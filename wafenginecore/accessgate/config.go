// Package accessgate 承载「统一访问认证(Access 模式)」的运行时配置快照与策略判定。
//
// 为什么单独开一个叶子包而不是直接放在 wafenginecore 里：
// 写入侧是 service/waf_service（管理端保存配置时发布快照），判定侧是 wafenginecore（请求热路径）。
// 而 wafenginecore 已经 import 了 service/waf_service（见 wafworker.go / sslorder.go），
// 反向再 import 就是 import cycle。ipset、clientip 两个包出于同样的原因存在，本包与它们同层。
//
// 为什么用全局原子快照而不是把配置塞进每个站点的 HostSafe：
// Access 的全局配置是租户级的，改一次要让所有站点同时生效。若展开进各站点，
// 改一次配置就要对每个站点做一次 UpdateHost，而 UpdateHost 会 clone 整张路由表。
// 全局快照则是一次原子指针替换，零通道消息、零竞态、无中间不一致状态。
//
// 站点级的差异（三态开关、路径白名单）仍然放在 HostSafe.Host.AccessJSON 里，
// 随既有的 LoadHost 生效，不需要新增 ChanType。
package accessgate

import (
	"strings"
	"sync/atomic"
	"time"
)

// Config 是已经解析好的运行时配置。
//
// 它与 model.AccessConfig（落库结构）刻意分开：落库的是用户填的原始值（分钟、字符串、加密密文），
// 这里存的是引擎直接可用的形态（time.Duration、切片、解密后的密钥）。
// 每请求都要读的东西，不该在热路径上做字符串切分和解密。
//
// 一经发布即只读。任何变更都必须构造一份全新的 Config 再 SetConfig，
// 绝不能就地修改已发布的实例——热路径正在无锁读它。
type Config struct {
	// ForceDisable 是自救开关，来自 conf/config.yml 的 security.access_force_disable
	// 或环境变量 SAMWAF_ACCESS_DISABLE。它在 DoAccessGate 的最前面短路，早于一切其它判定。
	// 存在的意义：用户把管理端也反代进了 WAF 并开启 Access，一旦配错就会把自己彻底锁在外面。
	// 放 yml 而不是数据库，正是因为那种情况下管理端已经进不去了，只能改文件 + 重启自救。
	ForceDisable bool

	// GlobalEnable 来自 system_config 的 access_enable → global.GCONFIG_ACCESS_ENABLE。
	// 默认 0（关闭），存量用户升级后行为完全不变。
	GlobalEnable bool

	// CenterOrigin 是认证中心地址，配置页必填。为空说明用户还没配过（或认证中心站点
	// 被改了域名）——此时 DoAccessGate 直接放行并告警，因为没有认证中心就没有登录入口。
	// CenterHost 是从 CenterOrigin 解析出的 host[:port]，用于和请求的 r.Host 比对。
	CenterOrigin string
	CenterHost   string

	PathPrefix      string // 已归一化：小写、以 / 开头、无尾部 /
	CookieSSOName   string // 中心会话 Cookie 名，= CookiePrefix + "_sso"
	CookieTokenName string // 业务域子令牌 Cookie 名，= CookiePrefix + "_tk"
	CookiePrefix    string // 剥离 Cookie 时按此前缀匹配

	HmacSecret []byte // rq 签名密钥（已解密）

	SessionTTL  time.Duration
	TokenTTL    time.Duration
	TicketTTL   time.Duration
	IdleTimeout time.Duration // 0 = 不启用空闲超时

	BindIP          bool
	BindFingerprint bool
	RequireOtp      bool
	MaxFailCount    int
	LockDuration    time.Duration

	GlobalExcludePaths []string // 已小写、已去空行
	BypassIPGroupCode  string
	ServiceTokenHeader string
	ServiceTokenHashes []string // sha256hex，已小写

	UnauthAction       string
	PassIdentityHeader bool
	ForceSecureCookie  bool
	CachePositiveTTL   time.Duration
}

// disabledDefault 是快照未发布时的兜底。
//
// 关键属性：GlobalEnable=false。也就是说「配置还没加载出来」的窗口期一律放行，
// 而不是一律拦截。这个方向是刻意选的——启动早期误拦会让整站瞬间不可用，
// 而误放行只是让防护晚生效几十毫秒。真正的防护由 main.go 在 StartWaf() 之前
// 同步发布一次快照来保证，见 waf_access_config_service.go 的 PublishConfig。
var disabledDefault = &Config{
	GlobalEnable:     false,
	PathPrefix:       "/samwaf_access",
	CookieSSOName:    "samwaf_ac_sso",
	CookieTokenName:  "samwaf_ac_tk",
	CookiePrefix:     "samwaf_ac",
	UnauthAction:     "auto",
	MaxFailCount:     10,
	LockDuration:     3 * time.Minute,
	CachePositiveTTL: 60 * time.Second,
}

var snapshot atomic.Pointer[Config]

// Get 返回当前快照。热路径无锁读，永不返回 nil。
func Get() *Config {
	if c := snapshot.Load(); c != nil {
		return c
	}
	return disabledDefault
}

// SetConfig 原子替换整份配置。传 nil 会退回到「全部关闭」的兜底配置。
func SetConfig(c *Config) {
	if c == nil {
		snapshot.Store(disabledDefault)
		return
	}
	snapshot.Store(c)
}

// IsCenterMode 是否配置了认证中心（即是否启用真 SSO）。
func (c *Config) IsCenterMode() bool {
	return c != nil && c.CenterOrigin != "" && c.CenterHost != ""
}

// 站点级三态。与 model.AccessMode* 保持同值，这里重复定义是为了让本包保持叶子性
// （不 import model，避免把整个 model 包拖进这个被 service 依赖的叶子包）。
const (
	ModeInherit  = 0
	ModeForceOn  = 1
	ModeForceOff = 2
)

// IsAccessEnabled 是「这个站点此刻要不要做访问认证」的唯一权威判定。
//
//	ModeForceOn  强制开：全局关也要认证 —— 让用户可以只保护一个后台站点，不必先开全局
//	ModeForceOff 强制关：全局开也放行 —— 让用户敢开全局，公开站点单独豁免
//	ModeInherit  继承  ：跟随全局总开关（默认，也是存量站点的取值）
//
// 只在这一处实现，判定散落到多处必然会漂移。
func IsAccessEnabled(mode int, globalEnable bool) bool {
	switch mode {
	case ModeForceOn:
		return true
	case ModeForceOff:
		return false
	default:
		return globalEnable
	}
}

// MatchPathPrefix 判断请求路径是否命中免认证路径白名单。
//
// 匹配的是「路径段边界」而不是裸字符串前缀：写 /api/webhook 会放行
// /api/webhook 与 /api/webhook/github，但不会放行 /api/webhook_admin。
// 裸前缀匹配在这里是危险的——白名单是给健康检查、webhook 这类调用方开的口子，
// 用户想放行的是一棵子树，而不是"所有以这串字符开头的路径"，
// 后者会让一个 /admin 白名单顺手把 /adminconsole 也放出去。
//
// 调用方须先把 p 归一化（小写 + path.Clean）。
//
// 空条目会被 BuildExcludePaths 过滤掉。若不过滤，一个空行就等于 "" 前缀，
// 会匹配所有路径 —— 用户多敲一个回车就把整站认证关掉了。
func MatchPathPrefix(p string, list []string) bool {
	for _, item := range list {
		if item == "" {
			continue
		}
		if p == item {
			return true
		}
		// item 自带尾斜杠时直接按前缀比；否则补一个斜杠，确保只在段边界上匹配
		if strings.HasSuffix(item, "/") {
			if strings.HasPrefix(p, item) {
				return true
			}
		} else if strings.HasPrefix(p, item+"/") {
			return true
		}
	}
	return false
}

// BuildExcludePaths 把用户填的多行文本解析成可直接匹配的前缀列表。
// 同时接受换行与逗号分隔；会去空白、转小写、丢弃空条目。
func BuildExcludePaths(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	replaced := strings.NewReplacer("\r\n", "\n", "\r", "\n", ",", "\n").Replace(raw)
	var out []string
	for _, line := range strings.Split(replaced, "\n") {
		item := strings.ToLower(strings.TrimSpace(line))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

// NormalizePathPrefix 归一化路径前缀：转小写、补前导 /、去尾部 /。
// 传入非法值（空、只有 /）时回退到默认前缀，保证引擎侧永远有一个可用的自服务路径。
func NormalizePathPrefix(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if p == "" {
		return disabledDefault.PathPrefix
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return disabledDefault.PathPrefix
	}
	return p
}
