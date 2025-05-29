package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"io"
	"strings"
	"time"
)

// StreamProcessor 流式内容处理器
type StreamProcessor struct {
	originalReader io.ReadCloser
	wafEngine      *WafEngine
	wafContext     innerbean.WafHttpContextData
	hostCode       string
	buffer         []byte
	lineBuffer     strings.Builder
	isInEvent      bool
}

// 创建流式处理器
func (waf *WafEngine) createStreamProcessor(originalBody io.ReadCloser, wafContext innerbean.WafHttpContextData, hostCode string) *StreamProcessor {
	return &StreamProcessor{
		originalReader: originalBody,
		wafEngine:      waf,
		wafContext:     wafContext,
		hostCode:       hostCode,
		buffer:         make([]byte, 0, 4096),
	}
}

// Read 实现io.Reader接口
func (sp *StreamProcessor) Read(p []byte) (n int, err error) {
	// 从原始流读取数据
	tempBuf := make([]byte, len(p))
	n, err = sp.originalReader.Read(tempBuf)
	if n > 0 {
		// 将读取的数据添加到缓冲区
		sp.buffer = append(sp.buffer, tempBuf[:n]...)

		// 处理完整的行
		processedData := sp.processStreamData()

		// 将处理后的数据复制到输出缓冲区
		copyLen := len(processedData)
		if copyLen > len(p) {
			copyLen = len(p)
		}
		copy(p, processedData[:copyLen])

		// 如果处理后的数据超过了输出缓冲区大小，保留剩余部分
		if len(processedData) > copyLen {
			sp.buffer = append(processedData[copyLen:], sp.buffer...)
		}

		return copyLen, err
	}
	return n, err
}

// Close 实现io.Closer接口
func (sp *StreamProcessor) Close() error {
	if sp.originalReader != nil {
		return sp.originalReader.Close()
	}
	return nil
}

// 处理流式数据
func (sp *StreamProcessor) processStreamData() []byte {
	data := string(sp.buffer)
	lines := strings.Split(data, "\n")
	var processedLines []string

	// 处理除最后一行外的所有完整行(最后一行可能不完整)
	for i := 0; i < len(lines)-1; i++ {
		line := lines[i]
		processedLine := sp.processLine(line)
		processedLines = append(processedLines, processedLine)
	}

	// 保留最后一行未完整的数据
	if len(lines) > 0 {
		sp.buffer = []byte(lines[len(lines)-1])
	} else {
		sp.buffer = sp.buffer[:0]
	}

	result := strings.Join(processedLines, "\n")
	if len(processedLines) > 0 {
		result += "\n"
	}

	return []byte(result)
}

// 处理单行数据
func (sp *StreamProcessor) processLine(line string) string {
	// 检查是否是SSE数据行
	if strings.HasPrefix(line, "data:") {
		// 提取事件数据
		eventData := strings.TrimPrefix(line, "data:")
		eventData = strings.TrimSpace(eventData)

		// 进行隐私保护处理
		processedData := sp.processPrivacyProtection(eventData)

		// 进行敏感词检测和替换
		processedData = sp.processSensitiveWords(processedData)

		return "data: " + processedData
	}

	// 对于非数据行，也进行基本的敏感词检测
	return sp.processSensitiveWords(line)
}

// 隐私保护处理
func (sp *StreamProcessor) processPrivacyProtection(data string) string {
	// 检查是否需要进行隐私保护
	host := sp.wafEngine.HostCode[sp.wafContext.HostCode]
	lowerRequestURI := strings.ToLower(sp.wafContext.Weblog.URL)

	ldpFlag := false

	// 检查局部隐私保护规则
	for i := 0; i < len(sp.wafEngine.HostTarget[host].LdpUrlLists); i++ {
		lowerRuleURL := strings.ToLower(sp.wafEngine.HostTarget[host].LdpUrlLists[i].Url)

		if (sp.wafEngine.HostTarget[host].LdpUrlLists[i].CompareType == "等于" && lowerRuleURL == lowerRequestURI) ||
			(sp.wafEngine.HostTarget[host].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerRuleURL)) ||
			(sp.wafEngine.HostTarget[host].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerRuleURL)) ||
			(sp.wafEngine.HostTarget[host].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerRuleURL)) {
			ldpFlag = true
			break
		}
	}

	// 检查全局隐私保护规则
	if !ldpFlag {
		for i := 0; i < len(sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists); i++ {
			lowerGlobalRuleURL := strings.ToLower(sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].Url)

			if (sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerRequestURI) ||
				(sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(sp.wafEngine.HostTarget[global.GWAF_GLOBAL_HOST_NAME].LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerGlobalRuleURL)) {
				ldpFlag = true
				break
			}
		}
	}

	// 如果需要隐私保护，进行脱敏处理
	if ldpFlag {
		return utils.DeSenText(data)
	}

	return data
}

// 敏感词检测和替换
func (sp *StreamProcessor) processSensitiveWords(data string) string {
	// 检查是否启用敏感词检测
	if !sp.wafEngine.CheckResponseSensitive() {
		return data
	}

	// 进行敏感词检测
	matchResult := sp.wafEngine.SensitiveManager.MultiPatternSearch([]rune(data), false)
	if len(matchResult) > 0 {
		processedData := data
		detectedWordsMap := make(map[string]bool) // 使用map去重
		var detectedWords []string
		var hasDenyAction bool

		for _, match := range matchResult {
			sensitive := match.CustomData.(model.Sensitive)
			word := string(match.Word)

			if sensitive.CheckDirection != "in" {
				// 检查是否已经存在，避免重复添加
				if !detectedWordsMap[word] {
					detectedWordsMap[word] = true
					detectedWords = append(detectedWords, word)
				}

				if sensitive.Action == "deny" {
					hasDenyAction = true
				} else {
					// 替换敏感词
					processedData = strings.ReplaceAll(processedData, word, global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
				}
			}
		}

		// 统一记录一次日志，避免重复记录
		if len(detectedWords) > 0 {
			if hasDenyAction {
				sp.logSensitiveDetection(detectedWords, "deny", data)
				// 对于拒绝动作，返回屏蔽信息
				return "data: [敏感内容已屏蔽]\n"
			} else {
				sp.logSensitiveDetection(detectedWords, "replace", data)
			}
		}

		return processedData
	}

	return data
}

// 记录敏感词检测日志
func (sp *StreamProcessor) logSensitiveDetection(words []string, action string, data string) {
	datetimeNow := time.Now()
	sp.wafContext.Weblog.REQ_UUID = uuid.GenUUID()
	sp.wafContext.Weblog.RISK_LEVEL = 1
	sp.wafContext.Weblog.GUEST_IDENTIFICATION = "触发敏感词"
	sp.wafContext.Weblog.RULE = "敏感词检测：" + strings.Join(words, ",")
	sp.wafContext.Weblog.CREATE_TIME = datetimeNow.Format("2006-01-02 15:04:05")
	sp.wafContext.Weblog.UNIX_ADD_TIME = datetimeNow.UnixNano() / 1e6
	sp.wafContext.Weblog.RES_BODY = data

	// 可以选择立即记录日志或者累积后统一记录
	logEntry := *sp.wafContext.Weblog
	if action == "deny" {
		logEntry.ACTION = "阻止"
	} else {
		logEntry.ACTION = "放行"
	}

	// 异步记录日志，避免阻塞流处理
	go func() {
		global.GQEQUE_LOG_DB.Enqueue(logEntry)
	}()
}
