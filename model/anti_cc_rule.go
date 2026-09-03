package model

import (
	"SamWaf/model/baseorm"
	"crypto/rand"
	"encoding/json"
	"strings"
	"time"
)

// AntiCCRule 是一条 CC 防护规则。
//
// 与旧的 AntiCC（一个网站只能有一条）不同，同一网站可以有多条规则，按 Priority 升序执行，
// 命中即停（观察类动作除外）。执行顺序与优先级语义见 SamWafTechDoc/Plan 的实施计划 §5.1。
//
// 三组概念务必分清，混在一起是旧实现配不准阈值的根因：
//   - 匹配范围（MatchMode/MatchJson）：这条规则**管哪些请求**
//   - 统计口径（CountScope/ExcludeExts）：命中的请求里**哪些算一次**
//   - 统计维度（StatDim/StatDimField）：算进来的请求**按谁归堆**
//
// 表名与列名有意避开 waf_sql_query 的敏感规则（不含 config/account，
// 列名不用 value/params/key），参照 model/host_group.go 的说明。
type AntiCCRule struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64;index" json:"host_code"` //所属网站唯一码（全局站点用全局码）
	// RuleCode 短码，形如 CC-7F3A2B。攻击日志里带上它，管理员照着规则列表就能对上是哪条规则，
	// 比主键短、也不用把主键写进日志。**只用于后台展示，不出现在给访客看的页面上**：
	// 公开面上的稳定标识会让人逐条试出自己命中或绕过了哪条规则，访客侧一律用每请求随机的访问识别码。
	RuleCode string `gorm:"size:16;index" json:"rule_code"`
	RuleName string `gorm:"size:255" json:"rule_name"` //规则名
	Priority int    `json:"priority"`                  //执行优先级，越小越先执行
	IsEnable int    `json:"is_enable"`                 //1启用 0停用

	// ① 匹配范围
	MatchMode  string `gorm:"size:20" json:"match_mode"`   //all=全部请求 simple=结构化条件 expr=脚本条件
	MatchJson  string `gorm:"type:text" json:"match_json"` //MatchMode=simple 时的条件数组，见 MatchCondition
	MatchExpr  string `gorm:"type:text" json:"match_expr"` //MatchMode=expr 时的 grule 条件表达式（只写 when，不含动作）
	CountPhase string `gorm:"size:20" json:"count_phase"`  //request=请求期计数(默认) response=响应期计数

	// ② 统计口径
	CountScope  string `gorm:"size:20" json:"count_scope"`    //all/dynamic/document/origin_only
	ExcludeExts string `gorm:"type:text" json:"exclude_exts"` //CountScope=dynamic 时的静态后缀，空=用内置默认

	// ③ 统计维度
	StatDim      string `gorm:"size:20" json:"stat_dim"`       //ip/ip_uri/session/header/cookie/query/body/host_total
	StatDimField string `gorm:"size:64" json:"stat_dim_field"` //维度需要指定字段名时的名字（header/cookie/query/body）

	// ④ 窗口与阈值
	Algo      string `gorm:"size:20" json:"algo"` //window=近似滑窗(默认) token_bucket=令牌桶(兼容旧配置)
	WindowSec int    `json:"window_sec"`          //统计窗口(秒)
	Threshold int    `json:"threshold"`           //窗口内允许的最大次数
	Burst     int    `json:"burst"`               //突发容忍，吸收一次页面加载的并发子请求，0=不额外容忍

	// ⑤ 动作
	Action        string `gorm:"size:20" json:"action"`    //observe/deny/captcha/ban
	ActionSeconds int    `json:"action_seconds"`           //动作持续时长(秒)
	BanScope      string `gorm:"size:20" json:"ban_scope"` //Action=ban 时的作用域 host/global
	StopGlobal    int    `json:"stop_global"`              //1=本条命中后不再执行全局站点的规则

	// BotExempt 1=已验证的搜索引擎爬虫不计入本条规则的计数。
	//
	// 只对身份验证走完完整闭环的爬虫生效（正向确认的反向DNS，或厂商公布网段），
	// 仅反向匹配上、正向确认不了的不算——豁免的把握程度不能超过身份验证的把握程度。
	// 「观察」动作不受本开关影响：观察本来就不阻断，豁免了反而看不到爬虫的真实量。
	// 想给抓得过猛的爬虫单独限速时把它关掉，再用「是否机器人 = 1」的条件即可。
	BotExempt int `json:"bot_exempt"`

	Remarks  string `gorm:"size:500" json:"remarks"`
	HitCount int64  `gorm:"-" json:"hit_count"` //近期命中次数，列表接口聚合填充，不落库
}

// ccCodeAlphabet 去掉了 0/O/1/I/L 这些抄写时容易混的字符——这个码是要用户念给管理员的
const ccCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// GenCCRuleCode 生成一个规则短码。随机取值而不是按序号，避免从码本身推出规则的新建顺序与数量。
func GenCCRuleCode() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		// 拿不到随机源时退回时间来源，宁可弱一点也不要返回空码
		n := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(n >> (8 * uint(i%8)))
		}
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = ccCodeAlphabet[int(b)%len(ccCodeAlphabet)]
	}
	return "CC-" + string(out)
}

func (AntiCCRule) TableName() string {
	return "anti_cc_rules"
}

// —— 枚举白名单。前端传来的值一律不可信，保存前必须逐项过白名单。——

const (
	CCMatchModeAll    = "all"
	CCMatchModeSimple = "simple"
	CCMatchModeExpr   = "expr"
)

const (
	CCCountPhaseRequest  = "request"
	CCCountPhaseResponse = "response"
)

const (
	CCCountScopeAll        = "all"         // 全部请求（旧行为，迁移过来的存量配置用它）
	CCCountScopeDynamic    = "dynamic"     // 排除静态资源（新建规则默认）
	CCCountScopeDocument   = "document"    // 仅页面文档请求
	CCCountScopeOriginOnly = "origin_only" // 仅回源未命中缓存的请求
)

const (
	CCStatDimIP        = "ip"
	CCStatDimIPURI     = "ip_uri"
	CCStatDimSession   = "session"
	CCStatDimHeader    = "header"
	CCStatDimCookie    = "cookie"
	CCStatDimQuery     = "query"
	CCStatDimBody      = "body"
	CCStatDimHostTotal = "host_total"
)

const (
	CCAlgoWindow      = "window"
	CCAlgoTokenBucket = "token_bucket"
)

const (
	CCActionObserve = "observe" // 仅记录，不阻断，且不中断后续规则
	CCActionDeny    = "deny"    // 拦截本次请求
	CCActionCaptcha = "captcha" // 转人机验证
	CCActionBan     = "ban"     // 写入封禁期
)

// CCDefaultExcludeExts 统计口径 dynamic 的内置静态后缀。
// 取值参照 OWASP CRS DoS 插件的 static_extensions，并补上常见字体与媒体后缀。
var CCDefaultExcludeExts = []string{
	".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
	".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".bmp", ".avif",
}

// CCStatDimNeedsField 判断该统计维度是否必须指定字段名。
func CCStatDimNeedsField(dim string) bool {
	switch dim {
	case CCStatDimHeader, CCStatDimCookie, CCStatDimQuery, CCStatDimBody:
		return true
	}
	return false
}

// CCStatDimForgeable 判断该统计维度是否可被客户端伪造。
//
// 这类维度只要攻击者每个请求换一个值就能绕开限频，界面必须给出提示；
// 它同时也是计数器 key 膨胀的来源，落地时要配合截断、哈希与配额。
func CCStatDimForgeable(dim string) bool {
	switch dim {
	case CCStatDimHeader, CCStatDimCookie, CCStatDimQuery, CCStatDimBody, CCStatDimSession:
		return true
	}
	return false
}

var (
	ccValidMatchModes  = map[string]bool{CCMatchModeAll: true, CCMatchModeSimple: true, CCMatchModeExpr: true}
	ccValidCountPhases = map[string]bool{CCCountPhaseRequest: true, CCCountPhaseResponse: true}
	ccValidCountScopes = map[string]bool{
		CCCountScopeAll: true, CCCountScopeDynamic: true,
		CCCountScopeDocument: true, CCCountScopeOriginOnly: true,
	}
	ccValidStatDims = map[string]bool{
		CCStatDimIP: true, CCStatDimIPURI: true, CCStatDimSession: true, CCStatDimHeader: true,
		CCStatDimCookie: true, CCStatDimQuery: true, CCStatDimBody: true, CCStatDimHostTotal: true,
	}
	ccValidAlgos   = map[string]bool{CCAlgoWindow: true, CCAlgoTokenBucket: true}
	ccValidActions = map[string]bool{
		CCActionObserve: true, CCActionDeny: true, CCActionCaptcha: true, CCActionBan: true,
	}
)

func IsValidCCMatchMode(v string) bool  { return ccValidMatchModes[v] }
func IsValidCCCountPhase(v string) bool { return ccValidCountPhases[v] }
func IsValidCCCountScope(v string) bool { return ccValidCountScopes[v] }
func IsValidCCStatDim(v string) bool    { return ccValidStatDims[v] }
func IsValidCCAlgo(v string) bool       { return ccValidAlgos[v] }
func IsValidCCAction(v string) bool     { return ccValidActions[v] }

// ExcludeExtList 返回本规则实际生效的静态后缀清单（未配置时用内置默认）。
// 逐项归一化成小写并补上前导点，用户填 "js" 或 "JS" 都能命中。
func (r *AntiCCRule) ExcludeExtList() []string {
	raw := strings.TrimSpace(r.ExcludeExts)
	if raw == "" {
		return CCDefaultExcludeExts
	}
	seps := strings.FieldsFunc(raw, func(c rune) bool {
		return c == ',' || c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == ';'
	})
	out := make([]string, 0, len(seps))
	for _, item := range seps {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if !strings.HasPrefix(item, ".") {
			item = "." + item
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return CCDefaultExcludeExts
	}
	return out
}

// Conditions 解析结构化匹配条件。MatchMode 不是 simple 时返回空。
func (r *AntiCCRule) Conditions() ([]MatchCondition, error) {
	if r.MatchMode != CCMatchModeSimple || strings.TrimSpace(r.MatchJson) == "" {
		return nil, nil
	}
	var conds []MatchCondition
	if err := json.Unmarshal([]byte(r.MatchJson), &conds); err != nil {
		return nil, err
	}
	return conds, nil
}
