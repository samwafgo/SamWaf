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

// maxStreamLineBytes 单行(单条 SSE 事件)在内存里最多攒多少字节。
// 超过就把已攒的原始字节原样放行，不再等换行 —— 只是这段内容躲过按行的敏感词/脱敏扫描，
// 字节仍然是无损的。目的是防止上游发一条没有换行的超长内容把内存吃干。
const maxStreamLineBytes = 1 << 20 // 1MB

// StreamProcessor 流式内容处理器
type StreamProcessor struct {
	originalReader io.ReadCloser
	wafEngine      *WafEngine
	wafContext     innerbean.WafHttpContextData
	hostCode       string
	buffer         []byte // 上游读来但还没凑成完整行的原始字节
	pending        []byte // 已处理完、等着交给调用方的字节
	readBuf        []byte // 复用的上游读缓冲，避免每次 Read 都分配
	eofSeen        bool   // 上游是否已结束
	eofErr         error  // 上游结束时带回来的错误(通常是 io.EOF)
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
//
// 分两级缓冲：buffer 存还没凑成完整行的原始字节，pending 存已处理好待交付的字节。
// 两者必须分开 —— 早期实现把"处理完但一次没塞下"的数据又塞回 buffer，既会被二次处理，
// 又在上游返回 (0, io.EOF) 时连同未交付的部分一起丢掉：表现为单条 SSE 事件只要超过
// 调用方的读缓冲(net/http 反代默认 32KB)就被截断、流提前结束。
// 对应 issue #949 / #954：Codex 报 "stream closed before response.completed" 后反复重试。
func (sp *StreamProcessor) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		// 1) 先把处理好的数据交出去；一次装不下的留到下次，绝不丢弃
		if len(sp.pending) > 0 {
			n := copy(p, sp.pending)
			sp.pending = sp.pending[n:]
			if len(sp.pending) == 0 {
				sp.pending = nil
			}
			return n, nil
		}

		// 2) 上游已结束：先把残留的不完整行冲刷出去，再向调用方报结束
		if sp.eofSeen {
			if len(sp.buffer) > 0 {
				tail := string(sp.buffer)
				sp.buffer = sp.buffer[:0]
				sp.pending = append(sp.pending, sp.processLine(tail)...)
				continue
			}
			return 0, sp.eofErr
		}

		// 3) 向上游取数据。读到的还不足一行就继续读，不返回 (0, nil) 让调用方空转
		if cap(sp.readBuf) < len(p) {
			sp.readBuf = make([]byte, len(p))
		}
		tempBuf := sp.readBuf[:len(p)]
		n, err := sp.originalReader.Read(tempBuf)
		if n > 0 {
			sp.buffer = append(sp.buffer, tempBuf[:n]...)
			if processed := sp.processStreamData(); len(processed) > 0 {
				sp.pending = append(sp.pending, processed...)
			}
			// 上游一直不发换行时，攒到上限就原样放行，避免内存无限增长
			if len(sp.pending) == 0 && len(sp.buffer) >= maxStreamLineBytes {
				sp.pending = append(sp.pending, sp.buffer...)
				sp.buffer = sp.buffer[:0]
			}
		}
		if err != nil {
			sp.eofSeen = true
			sp.eofErr = err
		}
	}
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
		trimmed := strings.TrimSpace(eventData)

		// 进行隐私保护处理
		processedData := sp.processPrivacyProtection(trimmed)

		// 进行敏感词检测和替换
		processedData = sp.processSensitiveWords(processedData)

		// 脱敏/敏感词都没改动内容时原样返回：重新拼 "data: " 会吃掉行尾的 、
		// 以及 SSE 里有意义的多余前导空格，未开启相关功能的站点不该被改一个字节。
		if processedData == trimmed {
			return line
		}

		return "data: " + processedData
	}

	// 对于非数据行，也进行基本的敏感词检测
	return sp.processSensitiveWords(line)
}

// 隐私保护处理
func (sp *StreamProcessor) processPrivacyProtection(data string) string {
	// 检查是否需要进行隐私保护
	host := sp.wafEngine.rt().HostCode[sp.wafContext.HostCode]
	lowerRequestURI := strings.ToLower(sp.wafContext.Weblog.URL)

	ldpFlag := false

	// 检查局部隐私保护规则
	//注意：host 解析不到时 HostTarget[host] 为 nil，必须判空，否则解引用 panic
	localHost := sp.wafEngine.rt().HostTarget[host]
	if localHost != nil {
		for i := 0; i < len(localHost.LdpUrlLists); i++ {
			lowerRuleURL := strings.ToLower(localHost.LdpUrlLists[i].Url)

			if (localHost.LdpUrlLists[i].CompareType == "等于" && lowerRuleURL == lowerRequestURI) ||
				(localHost.LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerRuleURL)) ||
				(localHost.LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerRuleURL)) ||
				(localHost.LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerRuleURL)) {
				ldpFlag = true
				break
			}
		}
	}

	// 检查全局隐私保护规则
	//注意：全局网站可能还没登记进路由快照（未初始化/正在重载），必须判空，否则解引用 panic
	globalHost := sp.wafEngine.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]
	if !ldpFlag && globalHost != nil {
		for i := 0; i < len(globalHost.LdpUrlLists); i++ {
			lowerGlobalRuleURL := strings.ToLower(globalHost.LdpUrlLists[i].Url)

			if (globalHost.LdpUrlLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerRequestURI) ||
				(globalHost.LdpUrlLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(globalHost.LdpUrlLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerRequestURI, lowerGlobalRuleURL)) ||
				(globalHost.LdpUrlLists[i].CompareType == "包含匹配" && strings.Contains(lowerRequestURI, lowerGlobalRuleURL)) {
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
