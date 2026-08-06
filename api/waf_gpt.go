package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/wafsec"
	"SamWaf/waftask"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type WafGPTApi struct {
}

// ============ 规则生成提示词（唯一来源，中英） ============
// 后端是提示词的唯一来源：内联 AI 生成用作 system prompt；前端"复制AI提示词"通过
// /api/v1/wafhost/rule/aiprompt 接口取用（GetRuleAiPrompt）。改这里一处即可，前端不再各存一份。
//
// 结构：知识主体(ruleAiKnowledgeXX) + 需求填空段(ruleAiRequireXX)
//   - 内联生成系统提示词 = 知识主体（意图由 user 消息单独传入）
//   - 复制给AI的完整提示词 = 知识主体 + 需求填空段

// ruleAiKnowledgeZH 规则知识主体（结构/字段/函数/动作/约束/示例）
const ruleAiKnowledgeZH = `你是 SamWaf（Go 编写的开源 WAF）自定义规则专家。请根据需求生成一条 SamWaf 规则脚本（GRL 语法）。只输出规则文本本身，不要解释、不要 markdown 代码块标记。

# 规则结构
rule R<唯一标识> "规则中文描述" salience <优先级数字> {
    when
        <条件表达式>
    then
        <动作>
}
说明：
- R<唯一标识>：规则名，以大写 R 开头，只能由字母和数字组成（不含横线）。
- salience：优先级，数值越大越优先。站点规则和全局规则一起按 salience 仲裁，同优先级时按 拦截 > 放行 > 仅记录 取。默认写 10；放行类要压过全局拦截规则时写 100。
- when：条件，为 true 时命中。then：命中后的动作，必须写且只能写一个。

# 可用请求字段（MF 开头，代表当前请求）
MF.HOST 请求域名 | MF.URL 请求地址 | MF.REFERER 来源页 | MF.USER_AGENT UA | MF.METHOD 请求方法 | MF.COOKIES Cookie | MF.BODY 请求体 | MF.PORT 端口(数值) | MF.SRC_IP 访客IP | MF.COUNTRY 国家(中文如"中国") | MF.PROVINCE 省 | MF.CITY 市
字段方法：
- MF.<字符串字段>.Contains("子串") == true / HasPrefix("前缀") == true / HasSuffix("后缀") == true
- MF.GetHeaderValue("头名").Contains("值") == true    取任意请求头再判断
- MF.GetIPFailureCount(分钟数) > 次数                 该IP近N分钟失败次数
- MF.IsSafeBot() == true                              是否搜索引擎等安全爬虫

# 可用规则函数（RF 开头，返回布尔，用在 when）
RF.IPMatch(MF.SRC_IP,"10.10.*.*")==true（单IP/CIDR/通配符/区间统一匹配，推荐优先用它；IPv4通配按八位组、*可在任意位置，IPv6通配须写满8段且不能用::，区间写"起-止"） | RF.IPInGroup(MF.SRC_IP,"办公室出口")==true（IP组，可跨站点复用的IP集合，在 网站防护-IP组 维护，可传组名或组短码） | RF.IPInRange(MF.SRC_IP,"起","止")==true | RF.IPInRanges(MF.SRC_IP,"起-止","CIDR","10.10.*.*",...)==true | RF.IPInCIDR(MF.SRC_IP,"192.168.1.0/24")==true | RF.IPEquals(MF.SRC_IP,"1.2.3.4")==true | RF.In(MF.METHOD,"GET","POST")==true | RF.InIgnoreCase(值,列表...)==true | RF.ContainsAny(MF.URL,"a","b")==true | RF.ContainsAnyIgnoreCase(MF.USER_AGENT,...)==true | RF.ContainsAll(MF.URL,"a","b")==true | RF.StartsWithAny(MF.URL,"/admin")==true | RF.EndsWithAny(MF.URL,".php")==true | RF.IntInRange(MF.PORT,8000,9000)==true | RF.IntIn(MF.PORT,80,443)==true | RF.Not(表达式)==true | RF.IsEmpty(值)==true | RF.IsNotEmpty(值)==true | RF.LengthBetween(MF.URL,0,512)==true
条件之间用 &&(且) 或 ||(或) 连接。

# 命中动作（then 里，四选一）
RF.Deny();            拦截（默认）
RF.Log();             仅记录不拦截（灰度观察）
RF.Allow();           放行（后续检测照常）
RF.Allow("CC","AI");  放行并跳过指定检测模块
RF.AllowAll();        放行并跳过后续所有检测
可跳过模块：BOT SQLI XSS SCAN RCE DIR CC AI SENSITIVE OWASP ANTILEECH CSRF UPLOAD CAPTCHA（不区分大小写）。
跳过 CC/SQLI 等前置检测需管理员在【系统配置 rule_chain_mode】设为"规则优先"。

# 硬性约束
1. 只能生成一条规则（一个 rule 块）；如需多条则分别输出，规则名不同。
2. 字符串值含双引号或反斜杠要转义（\" 和 \\），不要出现换行。
3. then 有且只有一个动作，不需要写 Retract。
4. 国家/省/市用中文；HTTP 方法用大写；规则名只能字母数字。

# 输出示例
rule Raiexample01 "拦截海外访问" salience 10 {
    when
        MF.COUNTRY != "中国"
    then
        RF.Deny();
}`

// ruleAiRequireZH "复制给AI"提示词末尾的需求填空段
const ruleAiRequireZH = `

# 我的需求
- 网站/业务：<填写，例如：只面向国内用户的博客站>
- 想做的防护：<填写，例如：只允许中国大陆访问，其余地区拦截>
- 命中后动作：<拦截 / 仅记录观察 / 放行，默认拦截>
- 优先级(可选)：<不填默认 10>`

// ruleAiKnowledgeEN 规则知识主体（英文）
const ruleAiKnowledgeEN = `You are an expert on SamWaf (an open-source WAF written in Go) custom rules. Based on the requirement, generate ONE SamWaf rule script (GRL syntax). Output ONLY the rule text, no explanation, no markdown code fences.

# Rule structure
rule R<uniqueId> "rule description" salience <priority> {
    when
        <condition>
    then
        <action>
}
Notes:
- R<uniqueId>: rule name, starts with uppercase R, letters and digits only (no dash).
- salience: priority, higher wins. Site rules and global rules are arbitrated together by salience; on a tie the order is deny > allow > log. Use 10 by default; use 100 for allow rules that must override a global deny rule.
- when: condition; matches when true. then: exactly one action.

# Request fields (MF = current request)
MF.HOST host | MF.URL url | MF.REFERER referer | MF.USER_AGENT UA | MF.METHOD method | MF.COOKIES cookies | MF.BODY body | MF.PORT port(number) | MF.SRC_IP client IP | MF.COUNTRY country(Chinese, e.g. "中国") | MF.PROVINCE | MF.CITY
Field methods:
- MF.<stringField>.Contains("s") == true / HasPrefix("p") == true / HasSuffix("s") == true
- MF.GetHeaderValue("Name").Contains("v") == true    read any request header
- MF.GetIPFailureCount(minutes) > n                   IP failure count in last N minutes
- MF.IsSafeBot() == true                              is a known safe bot (search engine)

# Rule functions (RF, return bool, used in when)
RF.IPMatch(MF.SRC_IP,"10.10.*.*")==true (unified matcher for single IP / CIDR / wildcard / range, prefer this one; IPv4 wildcard is per-octet and * may appear anywhere, IPv6 wildcard must spell out all 8 groups and cannot mix with ::, range is written "start-end") | RF.IPInGroup(MF.SRC_IP,"office-egress")==true (IP group, a reusable cross-site IP set maintained under Site Protection - IP Group; accepts group name or group code) | RF.IPInRange(MF.SRC_IP,"start","end")==true | RF.IPInRanges(MF.SRC_IP,"start-end","CIDR","10.10.*.*",...)==true | RF.IPInCIDR(MF.SRC_IP,"192.168.1.0/24")==true | RF.IPEquals(MF.SRC_IP,"1.2.3.4")==true | RF.In(MF.METHOD,"GET","POST")==true | RF.InIgnoreCase(v,list...)==true | RF.ContainsAny(MF.URL,"a","b")==true | RF.ContainsAnyIgnoreCase(MF.USER_AGENT,...)==true | RF.ContainsAll(MF.URL,"a","b")==true | RF.StartsWithAny(MF.URL,"/admin")==true | RF.EndsWithAny(MF.URL,".php")==true | RF.IntInRange(MF.PORT,8000,9000)==true | RF.IntIn(MF.PORT,80,443)==true | RF.Not(expr)==true | RF.IsEmpty(v)==true | RF.IsNotEmpty(v)==true | RF.LengthBetween(MF.URL,0,512)==true
Join conditions with && (and) or || (or).

# Actions (in then, pick one)
RF.Deny();            block (default)
RF.Log();             log only, no block (canary observation)
RF.Allow();           allow (later checks still run)
RF.Allow("CC","AI");  allow and skip given detection modules
RF.AllowAll();        allow and skip all later checks
Skippable modules: BOT SQLI XSS SCAN RCE DIR CC AI SENSITIVE OWASP ANTILEECH CSRF UPLOAD CAPTCHA (case-insensitive).
Skipping front checks like CC/SQLI requires the admin to set System Config rule_chain_mode to "Rule First".

# Hard constraints
1. Generate exactly one rule (one rule block); if multiple are needed, output each separately with distinct names.
2. Escape double quotes and backslashes in string values (\" and \\); no newlines inside strings.
3. Exactly one action in then; no Retract needed.
4. Country/Province/City in Chinese; HTTP methods uppercase; rule name letters+digits only.

# Output example
rule Raiexample01 "Block overseas access" salience 10 {
    when
        MF.COUNTRY != "中国"
    then
        RF.Deny();
}`

// ruleAiRequireEN "复制给AI"提示词末尾的需求填空段（英文）
const ruleAiRequireEN = `

# My requirements
- Site/business: <fill in, e.g. a blog for domestic users only>
- Protection goal: <fill in, e.g. allow only mainland China, block others>
- Action on match: <block / log-only / allow, default block>
- Priority (optional): <default 10>`

// 内联 AI 生成的系统提示词 = 知识主体（意图作为 user 消息单独传入）
const ruleGenSystemPromptZH = ruleAiKnowledgeZH
const ruleGenSystemPromptEN = ruleAiKnowledgeEN

// 完整"复制给AI"提示词 = 知识主体 + 需求填空段
const ruleAiPromptZH = ruleAiKnowledgeZH + ruleAiRequireZH
const ruleAiPromptEN = ruleAiKnowledgeEN + ruleAiRequireEN

// GetRuleAiPrompt 按语言返回"复制给AI"的完整提示词（供前端接口取用）
func GetRuleAiPrompt(lang string) string {
	if strings.HasPrefix(strings.ToLower(lang), "en") {
		return ruleAiPromptEN
	}
	return ruleAiPromptZH
}

// callGPTOnce 非流式调用一次 GPT，返回完整回复内容
func callGPTOnce(messages []model.GptMessage) (string, error) {
	gptReq := model.GPTRequest{
		Messages:       messages,
		Model:          global.GCONFIG_RECORD_GPT_MODEL,
		MaxTokens:      2048,
		ResponseFormat: model.GptResponseFormat{Type: "text"},
		Stream:         false,
		Temperature:    0.3, // 生成规则要稳定，降低随机性
		TopP:           1,
	}
	bodyBytes, _ := json.Marshal(gptReq)

	apiURL := global.GCONFIG_RECORD_GPT_URL
	if strings.HasSuffix(apiURL, "/v1") {
		apiURL += "/chat/completions"
	} else {
		apiURL += "/v1/chat/completions"
	}

	httpReq, err := http.NewRequest("POST", apiURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+global.GCONFIG_RECORD_GPT_TOKEN)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", fmt.Errorf("解析AI响应失败")
	}
	if parsed.Error != nil {
		return "", errors.New(parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("AI未返回内容")
	}
	return parsed.Choices[0].Message.Content, nil
}

// cleanRuleText 清洗 AI 返回文本：去掉 markdown 围栏和前后杂质，从第一个 rule 关键字开始
func cleanRuleText(s string) string {
	s = strings.TrimSpace(s)
	for _, fence := range []string{"```grl", "```GRL", "```go", "```json", "```"} {
		s = strings.ReplaceAll(s, fence, "")
	}
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "rule "); idx > 0 {
		s = s[idx:]
	}
	return strings.TrimSpace(s)
}

// ruleActionSemicolonRegex 匹配 then 里的动作调用（容忍空格），用于补分号
// 只在调用括号后紧跟位置处理分号，不吞掉后面的换行，保持格式
var ruleActionSemicolonRegex = regexp.MustCompile(`(RF\s*\.\s*(?:AllowAll|Allow|Deny|Log)\s*\([^)]*\))(;?)`)

// normalizeGeneratedRule 归一化 AI 生成的规则文本
// AI 常漏写动作末尾的分号，grule 会报 missing ';'。这里确定性地补上，不依赖模型自觉。
func normalizeGeneratedRule(s string) string {
	s = cleanRuleText(s)
	// 给每个动作调用补上分号（已有分号的不会重复）
	s = ruleActionSemicolonRegex.ReplaceAllString(s, "$1;")
	return s
}

// IsGPTConfigured GPT 是否已配置密钥
func IsGPTConfigured() bool {
	tok := strings.TrimSpace(global.GCONFIG_RECORD_GPT_TOKEN)
	return tok != "" && tok != "SamWaf提示请输入密钥"
}

// GetGptConfigApi 获取GPT参数（gpt_url/gpt_model/是否已配置密钥）
// 安全：token 是敏感凭证，接口只回传 has_token 布尔，绝不下发明文到浏览器（日志脱敏/防泄露原则）。
func (w *WafGPTApi) GetGptConfigApi(c *gin.Context) {
	response.OkWithDetailed(map[string]interface{}{
		"gpt_url":   global.GCONFIG_RECORD_GPT_URL,
		"gpt_model": global.GCONFIG_RECORD_GPT_MODEL,
		"has_token": IsGPTConfigured(),
	}, "获取成功", c)
}

// SaveGptConfigApi 保存GPT参数并同步到 global
// gpt_url/gpt_model 直接覆盖；gpt_token 为空表示保留原密钥（配合 GET 不回传明文），非空才更新。
func (w *WafGPTApi) SaveGptConfigApi(c *gin.Context) {
	var req request.WafGptConfigSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	items := []request.WafSystemConfigEditByItemReq{
		{Item: "gpt_url", Value: strings.TrimSpace(req.GptUrl)},
		{Item: "gpt_model", Value: strings.TrimSpace(req.GptModel)},
	}
	// 只有传了新密钥才更新，避免前端因不回传明文而把密钥清空
	if strings.TrimSpace(req.GptToken) != "" {
		items = append(items, request.WafSystemConfigEditByItemReq{Item: "gpt_token", Value: strings.TrimSpace(req.GptToken)})
	}
	for _, item := range items {
		if err := wafSystemConfigService.ModifyByItemApi(item); err != nil {
			response.FailWithMessage("保存失败: "+err.Error(), c)
			return
		}
	}
	// 重新加载配置到 global，热生效
	waftask.TaskLoadSetting(true)
	response.OkWithMessage("保存成功", c)
}

// ============ 对话场景与系统提示词 ============
// AI 助手是多入口共用的：日志详情点"AI分析"、OWASP 规则解读、右下角自由提问。
// 以前不管从哪来都硬套"信息安全专家 + 风险等级/风险类型/风险说明"这套格式，
// 结果随便问一句也被套成风险报告。这里按场景分开，前端发 scene，后端选提示词。
const (
	GptSceneSecurityLog = "security_log" // 日志详情：分析这条请求的安全风险
	GptSceneOwaspRule   = "owasp_rule"   // OWASP CRS 规则解读
	GptSceneGeneral     = "general"      // 通用问答（默认）
)

const gptSystemPromptSecurityLog = `你是一位信息安全专家，正在分析 SamWaf（Web 应用防火墙）记录到的一条 HTTP 请求。请判断这条请求是否存在攻击特征，输出如下格式：

风险等级: 0-100
风险类型:某种注入，跨站等
风险说明:对风险的阐释`

// gptDocRefs 官方资料索引。
// 注意：对话走的是标准 chat/completions，没有联网/检索工具，模型打不开任何网页。
// 所以这里不是"让它去搜"，而是给它一份**准确的地址清单**，让它把用户导向官方文档和 issues，
// 同时明确禁止它编造链接或假装读过页面——否则模型很容易凭空造出 /guide/XXX.html。
const gptDocRefs = `

# 官方资料（你没有联网能力，只能引用下面列出的地址；禁止编造其它链接，也不要声称自己读过页面内容）
- 文档站首页：https://doc.samwaf.com/
- 功能文档地址格式：https://doc.samwaf.com/guide/<页面名>.html（英文界面把 /guide/ 换成 /en/guide/）
- 可用的页面名（只能从这里挑，拿不准就只给文档站首页）：
  Host 网站配置 | Rule 防护规则 | CC CC防护 | Owasp OWASP规则集 | AIDetection AI智能检测 |
  IPBlack IP黑名单 | IPWhite IP白名单 | IPGroup IP组 | ThreatIP 威胁情报IP订阅 | FirewallIPBlock 防火墙IP封禁 |
  UrlBlack URL限制访问 | UrlWhite URL白名单 | Sensitive 敏感词 | Ldp URL隐私防护 | Spider 爬虫识别 |
  SSL SSL证书管理 | CDNIP CDN回源IP | Tunnel 隧道防护 | CacheRule 缓存规则 | Application 应用管理 |
  AttackLog 风险日志 | VisitLog 访问日志 | Analysis 数据分析 | BlockingPage 自定义拦截页 |
  NotifyChannel 通知渠道 | NotifySubscription 通知订阅 | NotifyLog 通知日志 |
  HttpAuthBase 网站访问认证 | AccessConfig 认证配置 | AccessAccount 访问账号 | AccessSession 在线会话 | AccessAudit 认证审计 |
  Account 账号管理 | Otp 双因素认证 | SystemConfig 系统配置 | VpConfig 参数设置 | PrivateInfo 密钥管理 |
  OpenPlatform 开放平台 | SqlQuery SQL查询 | Task 任务管理 | BatchTask 批量任务 | DataRetention 数据保留策略 |
  IPLocation IP数据库 | FileManage 文件管理 | RuntimeInfo 运行信息 | SysLog 系统日志 | OneKeyMod 一键修改
- 常见问题：https://doc.samwaf.com/faq/
- 安装与升级：https://doc.samwaf.com/quickstart/ 、https://doc.samwaf.com/quickstart/Update.html
- 已知问题与反馈：https://github.com/samwafgo/SamWaf/issues
  引导用户自己检索时，给出可直接点击的搜索地址：https://github.com/samwafgo/SamWaf/issues?q=is%3Aissue+关键词（多个关键词用 + 连接）

引用规则：
1. 回答涉及某个具体功能时，在结尾附上对应文档页链接。
2. 用户描述的现象像 bug、或你不确定当前版本是否支持，就直说"建议到 issues 搜一下，没有就提一个"，并给出上面的 issues 搜索地址。
3. 只给地址，不要转述你没有的页面内容，也不要编造文档里的章节名或配置项名称。`

const gptSystemPromptOwaspRule = `你是 OWASP ModSecurity 核心规则集(CRS)专家，正在帮用户读懂 SamWaf 里的一条 CRS 规则。请用简洁中文说明：
1. 这条规则想拦什么攻击；
2. 匹配条件的含义（变量、操作符、转换函数分别起什么作用）；
3. 常见误报场景；
4. 如果确认是误报，建议怎么处理（加白名单、调整阈值/等级、或对该规则单独放行）。
不要输出与规则无关的内容。` + gptDocRefs

const gptSystemPromptGeneral = `你是 SamWaf（一款开源轻量级 Web 应用防火墙）的智能助手，熟悉 Web 安全、网站防护、反向代理、SSL 证书、WAF 规则与告警等话题。
请直接回答用户的问题：用与用户提问相同的语言（默认中文），简洁作答，必要时分点说明；不知道就说不知道，不要编造 SamWaf 不存在的功能。
不要给回答强行套用固定模板或风险评分格式，除非用户明确要求。` + gptDocRefs

// gptSystemPromptByScene 按场景取系统提示词，未知场景一律按通用问答处理
func gptSystemPromptByScene(scene string) string {
	switch strings.TrimSpace(strings.ToLower(scene)) {
	case GptSceneSecurityLog:
		return gptSystemPromptSecurityLog
	case GptSceneOwaspRule:
		return gptSystemPromptOwaspRule
	default:
		return gptSystemPromptGeneral
	}
}

// 新增用于解析流式响应的结构体
type StreamResponse struct {
	ID                string         `json:"id"`
	Choices           []StreamChoice `json:"choices"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	SystemFingerprint string         `json:"system_fingerprint"`
	Object            string         `json:"object"`
	Usage             *TokenUsage    `json:"usage,omitempty"` // 只有最后一条消息包含
}

type StreamChoice struct {
	Index        int         `json:"index"`
	Delta        Delta       `json:"delta"`
	FinishReason *string     `json:"finish_reason"` // 使用指针类型处理 null
	Logprobs     interface{} `json:"logprobs"`
}

type Delta struct {
	Content string  `json:"content"`        // 内容增量
	Role    *string `json:"role,omitempty"` // 使用指针处理 null
}

type TokenUsage struct {
	CompletionTokens int `json:"completion_tokens"`
	PromptTokens     int `json:"prompt_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// buildDeltaPayload 组装一条加密后的 SSE 消息体
func buildDeltaPayload(content string, role string) (string, error) {
	encryptStr, _ := wafsec.AesEncrypt([]byte(content), global.GWAF_COMMUNICATION_KEY)
	msg := Delta{
		Content: encryptStr,
		Role:    &role,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// SendDeltaMessage 发送信息
func SendDeltaMessage(messageChan chan<- string, content string, role ...string) {
	// 设置默认角色为 assistant
	r := "assistant"
	if len(role) > 0 {
		r = role[0]
	}
	if payload, err := buildDeltaPayload(content, r); err == nil {
		messageChan <- payload
	}
}
func (w *WafGPTApi) ChatApi(c *gin.Context) {

	var req request.WafGptSendReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		// 以前这里静默返回，前端表现是"点了发送但气泡一直空着"，很难排查。
		// 注意 StreamMiddleware 已经把 Content-Type 定成 text/event-stream 了，
		// 这时候再 c.JSON 前端也当流读，所以错误也顺着 SSE 回，气泡里能直接看到。
		zlog.Error("GPT对话请求解析失败:" + err.Error())
		if payload, buildErr := buildDeltaPayload("对话请求解析失败："+err.Error(), "assistant"); buildErr == nil {
			c.SSEvent("message", payload)
		}
		return
	}
	{
		// 创建一个取消信号通道，用于触发异常退出
		stopChan := make(chan bool)
		messageChan := make(chan string)

		// 启动一个 goroutine，发送流请求并推送时间
		go func() {
			defer close(stopChan)
			defer close(messageChan)

			// 未配置密钥时不去请求空地址，直接回一条可读提示，前端也会在打开助手时先检测并引导配置
			if !IsGPTConfigured() {
				SendDeltaMessage(messageChan, "尚未配置AI密钥，请点击【AI 参数设置】填写接口地址/模型/密钥后再使用。", "assistant")
				stopChan <- true
				return
			}

			// 构造基础消息数组：系统提示词按场景取（日志分析/规则解读/通用问答）
			messages := []model.GptMessage{
				{
					Content: gptSystemPromptByScene(req.Scene),
					Role:    "system",
				},
			}
			// 将History内容转换为消息并追加
			for _, historyItem := range req.History {
				if len(historyItem) < 2 {
					continue // 跳过无效条目
				}
				if historyItem[1] == "远程服务器未返回信息，请检查配置" {
					continue
				}
				messages = append(messages, model.GptMessage{
					Role:    historyItem[0], // 角色类型（system/user/assistant）
					Content: historyItem[1], // 对话内容
				})
			}
			gptReq := model.GPTRequest{
				Messages:         messages,
				Model:            global.GCONFIG_RECORD_GPT_MODEL,
				FrequencyPenalty: 0,
				MaxTokens:        2048,
				PresencePenalty:  0,
				ResponseFormat:   model.GptResponseFormat{Type: "text"},
				Stop:             nil,
				Stream:           true,
				Temperature:      1,
				TopP:             1,
			}

			// 序列化为JSON字符串
			bodyBytes, _ := json.Marshal(gptReq)
			requestBody := string(bodyBytes)

			// 兼容两种URL格式：https://api.deepseek.com 和 https://api.deepseek.com/v1
			apiURL := global.GCONFIG_RECORD_GPT_URL
			if strings.HasSuffix(apiURL, "/v1") {
				// 如果URL已经以/v1结尾，只添加/chat/completions
				apiURL += "/chat/completions"
			} else {
				// 否则添加/v1/chat/completions
				apiURL += "/v1/chat/completions"
			}

			// 创建请求
			req, err := http.NewRequest("POST", apiURL, strings.NewReader(requestBody))
			if err != nil {
				stopChan <- true
				return
			}

			// 设置请求头
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "text/event-stream")
			req.Header.Set("Authorization", "Bearer "+global.GCONFIG_RECORD_GPT_TOKEN)

			// 创建 HTTP 客户端并发送请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				SendDeltaMessage(messageChan, fmt.Sprintf("访问报错%v", err.Error()), "assistant")
				stopChan <- true
				return
			}
			defer resp.Body.Close()

			// 读取流
			// 创建带缓冲的读取器
			reader := bufio.NewReader(resp.Body)
			var buffer bytes.Buffer
			var residual []byte

			for {
				// 读取数据块
				chunk := make([]byte, 1024)
				n, err := reader.Read(chunk)
				if err != nil && err != io.EOF {
					stopChan <- true
					return
				}

				// 合并残留数据和新数据
				buffer.Write(append(residual, chunk[:n]...))
				residual = nil

				// 分割数据包
				for {
					line, err := buffer.ReadBytes('\n')
					if err == io.EOF {
						// 判断残留数据中是否有错误信息
						lineStr := strings.TrimSpace(string(line))
						if strings.Contains(lineStr, `"error":`) {
							SendDeltaMessage(messageChan, fmt.Sprintf("Error: %s", lineStr), "assistant")
							stopChan <- true
							return
						}
						residual = line
						break
					}

					// 处理单行数据
					lineStr := strings.TrimSpace(string(line))
					if strings.HasPrefix(lineStr, "data: ") {
						content := strings.TrimPrefix(lineStr, "data: ")

						// 处理流结束标记
						if content == "[DONE]" {
							SendDeltaMessage(messageChan, "[DONE]", "assistant")
							stopChan <- true
							return
						}

						// 解析JSON数据
						var response StreamResponse
						if err := json.Unmarshal([]byte(content), &response); err != nil {
							continue // 忽略解析错误
						}

						// 处理消息内容
						for _, choice := range response.Choices {
							// 发送内容增量
							if choice.Delta.Content != "" {
								SendDeltaMessage(messageChan, choice.Delta.Content, "assistant")
							}

							// 处理停止条件
							if choice.FinishReason != nil && *choice.FinishReason == "stop" {
								stopChan <- true
								return
							}
						}
					}
				}

				if err == io.EOF {
					break
				}
			}
		}()

		c.Stream(func(w io.Writer) bool {
			// 判断是否接收到停止信号
			select {
			case <-stopChan:
				return false // 退出流式推送
			case message := <-messageChan:
				c.SSEvent("message", message) // 发送事件到客户端
				return true                   // 继续推送
			}
		})
	}
}
