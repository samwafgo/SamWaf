package api

import (
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
- salience：优先级，数值越大越先命中。默认写 10；放行类建议写 100 使其优先。
- when：条件，为 true 时命中。then：命中后的动作，必须写且只能写一个。

# 可用请求字段（MF 开头，代表当前请求）
MF.HOST 请求域名 | MF.URL 请求地址 | MF.REFERER 来源页 | MF.USER_AGENT UA | MF.METHOD 请求方法 | MF.COOKIES Cookie | MF.BODY 请求体 | MF.PORT 端口(数值) | MF.SRC_IP 访客IP | MF.COUNTRY 国家(中文如"中国") | MF.PROVINCE 省 | MF.CITY 市
字段方法：
- MF.<字符串字段>.Contains("子串") == true / HasPrefix("前缀") == true / HasSuffix("后缀") == true
- MF.GetHeaderValue("头名").Contains("值") == true    取任意请求头再判断
- MF.GetIPFailureCount(分钟数) > 次数                 该IP近N分钟失败次数
- MF.IsSafeBot() == true                              是否搜索引擎等安全爬虫

# 可用规则函数（RF 开头，返回布尔，用在 when）
RF.IPInRange(MF.SRC_IP,"起","止")==true | RF.IPInRanges(MF.SRC_IP,"起-止","CIDR",...)==true | RF.IPInCIDR(MF.SRC_IP,"192.168.1.0/24")==true | RF.IPEquals(MF.SRC_IP,"1.2.3.4")==true | RF.In(MF.METHOD,"GET","POST")==true | RF.InIgnoreCase(值,列表...)==true | RF.ContainsAny(MF.URL,"a","b")==true | RF.ContainsAnyIgnoreCase(MF.USER_AGENT,...)==true | RF.ContainsAll(MF.URL,"a","b")==true | RF.StartsWithAny(MF.URL,"/admin")==true | RF.EndsWithAny(MF.URL,".php")==true | RF.IntInRange(MF.PORT,8000,9000)==true | RF.IntIn(MF.PORT,80,443)==true | RF.Not(表达式)==true | RF.IsEmpty(值)==true | RF.IsNotEmpty(值)==true | RF.LengthBetween(MF.URL,0,512)==true
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
- salience: priority, higher wins first. Use 10 by default; use 100 for allow rules so they take precedence.
- when: condition; matches when true. then: exactly one action.

# Request fields (MF = current request)
MF.HOST host | MF.URL url | MF.REFERER referer | MF.USER_AGENT UA | MF.METHOD method | MF.COOKIES cookies | MF.BODY body | MF.PORT port(number) | MF.SRC_IP client IP | MF.COUNTRY country(Chinese, e.g. "中国") | MF.PROVINCE | MF.CITY
Field methods:
- MF.<stringField>.Contains("s") == true / HasPrefix("p") == true / HasSuffix("s") == true
- MF.GetHeaderValue("Name").Contains("v") == true    read any request header
- MF.GetIPFailureCount(minutes) > n                   IP failure count in last N minutes
- MF.IsSafeBot() == true                              is a known safe bot (search engine)

# Rule functions (RF, return bool, used in when)
RF.IPInRange(MF.SRC_IP,"start","end")==true | RF.IPInRanges(MF.SRC_IP,"start-end","CIDR",...)==true | RF.IPInCIDR(MF.SRC_IP,"192.168.1.0/24")==true | RF.IPEquals(MF.SRC_IP,"1.2.3.4")==true | RF.In(MF.METHOD,"GET","POST")==true | RF.InIgnoreCase(v,list...)==true | RF.ContainsAny(MF.URL,"a","b")==true | RF.ContainsAnyIgnoreCase(MF.USER_AGENT,...)==true | RF.ContainsAll(MF.URL,"a","b")==true | RF.StartsWithAny(MF.URL,"/admin")==true | RF.EndsWithAny(MF.URL,".php")==true | RF.IntInRange(MF.PORT,8000,9000)==true | RF.IntIn(MF.PORT,80,443)==true | RF.Not(expr)==true | RF.IsEmpty(v)==true | RF.IsNotEmpty(v)==true | RF.LengthBetween(MF.URL,0,512)==true
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

// SendDeltaMessage 发送信息
func SendDeltaMessage(messageChan chan<- string, content string, role ...string) {
	// 设置默认角色为 assistant
	r := "assistant"
	if len(role) > 0 {
		r = role[0]
	}
	encryptStr, _ := wafsec.AesEncrypt([]byte(content), global.GWAF_COMMUNICATION_KEY)
	// 创建消息结构
	msg := Delta{
		Content: encryptStr,
		Role:    &r,
	}

	// 序列化并发送
	if payload, err := json.Marshal(msg); err == nil {
		messageChan <- string(payload)
	}
}
func (w *WafGPTApi) ChatApi(c *gin.Context) {

	var req request.WafGptSendReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 创建一个取消信号通道，用于触发异常退出
		stopChan := make(chan bool)
		messageChan := make(chan string)

		// 启动一个 goroutine，发送流请求并推送时间
		go func() {
			defer close(stopChan)
			defer close(messageChan)

			// 构造基础消息数组
			messages := []model.GptMessage{
				{
					Content: "你是一位信息安全专家,输出如下格式：\n\n风险等级: 0-100\n风险类型:某种注入，跨站等\n风险说明:对风险的阐释",
					Role:    "user",
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
