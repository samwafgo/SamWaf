package wafowasp

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// maxRequestBodyBytes 请求体读取上限，与 coraza.conf 中的 SecRequestBodyLimit 保持一致（13MB）。
// 防止 io.ReadAll 在极端大请求体下出现无限分配。
const maxRequestBodyBytes = 13 * 1024 * 1024

// debugEnabled 是否开启 OWASP 详细日志（慢路径：采集全部 collection）。
// 本值由外部 bootstrap（例如 global.GWAF_LOG_DEBUG_ENABLE 变化时）通过 SetDebugEnabled 同步。
// 使用 atomic.Bool 避免与请求并发读的 race。
var debugEnabled atomic.Bool

// SetDebugEnabled 开启/关闭 OWASP 拦截详情的慢路径日志采集。
// 关闭时 handleInterruption 仅记录简短的 MatchedRules 信息，内存/CPU 友好。
func SetDebugEnabled(v bool) {
	debugEnabled.Store(v)
}

// IsDebugEnabled 返回当前是否开启详细日志。
func IsDebugEnabled() bool {
	return debugEnabled.Load()
}

// engineMode 当前引擎模式: "On" / "DetectionOnly" / "Off"。
// 由上层（main 启动、TuningSetApi、系统配置任务）通过 SetEngineMode 同步进来。
// Coraza 的 SecRuleEngine 指令已经负责实际拦截语义，这里只是让热路径能"知道"
// 当前是不是观察模式，以便命中而未拦截时用 INFO 记录"本该拦截"的日志。
var engineMode atomic.Value // string

// SetEngineMode 设置当前引擎工作模式。建议值："On" / "DetectionOnly" / "Off"。
// 空串按 "On" 处理。该值只影响 INFO 级的"观察模式本该拦截"日志，不改变 Coraza 实际行为。
func SetEngineMode(mode string) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "On"
	}
	engineMode.Store(mode)
}

// GetEngineMode 返回当前引擎工作模式，未设置时返回 "On"。
func GetEngineMode() string {
	if v := engineMode.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "On"
}

// bodyBufferPool 用于回放 r.Body 时复用底层缓冲区，降低 GC 压力。
var bodyBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// CustomLogger 自定义日志记录器，用于集成 zlog
type CustomLogger struct{}

func (l *CustomLogger) Error(msg string, fields map[string]interface{}) {
	zlog.Error(msg, fields)
}

type WafOWASP struct {
	IsActive bool       // 是否激活 WAF
	WAF      coraza.WAF // 对 Coraza WAF 实例的引用
	logger   *CustomLogger
}

// NewWafOWASP 创建新的 WAF 实例
func NewWafOWASP(isActive bool, currentDir string) *WafOWASP {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(currentDir + "/data/owasp/coraza.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/crs-setup.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/rules/*.conf")

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		zlog.Error("Failed to initialize WAF", map[string]interface{}{"error": err.Error()})
		return nil
	}

	logger := &CustomLogger{}

	return &WafOWASP{
		IsActive: isActive,
		WAF:      waf,
		logger:   logger,
	}
}

// ProcessRequest 处理 HTTP 请求。weblog 使用指针避免热路径上的结构体值拷贝（WebLog 可能内嵌 MB 级 BODY/RES_BODY）。
func (w *WafOWASP) ProcessRequest(r *http.Request, weblog *innerbean.WebLog) (bool, *types.Interruption, error) {
	if !w.IsActive || w.WAF == nil {
		return false, nil, nil
	}

	tx := w.WAF.NewTransaction()
	defer tx.Close()

	// 1. 处理连接信息
	if err := w.processConnection(tx, weblog, r); err != nil {
		return false, nil, fmt.Errorf("connection processing error: %v", err)
	}

	// 2. 处理请求行
	w.processRequestLine(tx, r)

	// 3. 处理请求头
	w.processRequestHeaders(tx, r)

	// 4. 检查请求头阶段的中断
	if it := tx.ProcessRequestHeaders(); it != nil {
		return w.handleInterruption(tx, it)
	}

	// 5. 处理请求体（流式，避免多份副本）
	if err := w.processRequestBody(tx, r, weblog); err != nil {
		return false, nil, fmt.Errorf("request body processing error: %v", err)
	}

	// 6. 检查请求体阶段的中断
	if it, err := tx.ProcessRequestBody(); err != nil {
		return false, nil, fmt.Errorf("request body processing error: %v", err)
	} else if it != nil {
		return w.handleInterruption(tx, it)
	}

	// 7. 检查最终的中断状态
	if tx.IsInterrupted() {
		if it := tx.Interruption(); it != nil {
			return w.handleInterruption(tx, it)
		}
		return true, nil, nil
	}

	// DetectionOnly 模式：Coraza 不会触发 disruptive action，tx.IsInterrupted 为 false。
	// 这里补一条 INFO 日志，告知管理员"本次若在 On 模式下会被拦截"，否则观察模式下用户看不到拦截痕迹。
	if GetEngineMode() == "DetectionOnly" {
		w.logDetectionOnlyWouldBlock(tx, r, weblog)
	}

	// 未拦截但 debug 模式打开：打出 Coraza 事务内所有 MatchedRules 和关键累计分，
	// 方便排查"真实访问没拦、沙盒能拦"这类差异（原因通常是：凑分规则未命中 / 阈值调太高 / 规则被禁用）。
	if debugEnabled.Load() {
		w.logNonInterruptTrace(tx)
	}

	return false, nil, nil
}

// logDetectionOnlyWouldBlock 观察模式下记录"本该被拦截"的请求。
//
// 判定条件：blocking_inbound_anomaly_score >= inbound_anomaly_score_threshold。
// 即：按当前 blocking_paranoia 口径累积的 PL 分数已经达到了拦截阈值。
//
// 由于 DetectionOnly 下 Coraza 会抑制 disruptive action，tx.IsInterrupted() 始终为 false；
// 用户只有在 On 模式切回去之前没机会看到任何命中记录，这里用 INFO 级别明确提示。
func (w *WafOWASP) logDetectionOnlyWouldBlock(tx types.Transaction, r *http.Request, weblog *innerbean.WebLog) {
	txState, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return
	}
	readInt := func(name string) int {
		if vals := txState.Variables().TX().Get(name); len(vals) > 0 {
			if v, err := strconv.Atoi(vals[0]); err == nil {
				return v
			}
		}
		return 0
	}

	threshold := readInt("inbound_anomaly_score_threshold")
	score := readInt("blocking_inbound_anomaly_score")
	if score == 0 {
		// 某些 CRS 版本下变量名不同，兜底再尝试两个常见别名
		if alt := readInt("anomaly_score"); alt > 0 {
			score = alt
		} else if alt := readInt("inbound_anomaly_score"); alt > 0 {
			score = alt
		}
	}
	if threshold <= 0 || score < threshold {
		return
	}

	matched := tx.MatchedRules()
	hits := make([]map[string]interface{}, 0, len(matched))
	for _, mr := range matched {
		if mr.Message() == "" {
			continue
		}
		rm := mr.Rule()
		hits = append(hits, map[string]interface{}{
			"id":       rm.ID(),
			"phase":    rm.Phase(),
			"severity": rm.Severity().String(),
			"msg":      mr.Message(),
		})
		// 命中统计：DetectionOnly 下记录观察模式命中
		if rm.ID() > 0 {
			GlobalHitStats.RecordDetected(rm.ID(), mr.Message(), rm.Severity().String())
		}
	}

	srcIP := ""
	if weblog != nil {
		srcIP = weblog.SRC_IP
	}

	zlog.Info("OWASP DetectionOnly 命中但未拦截(观察模式)", map[string]interface{}{
		"would_block":   true,
		"score":         score,
		"threshold":     threshold,
		"matched_total": len(hits),
		"matched":       hits,
		"method":        r.Method,
		"uri":           r.URL.RequestURI(),
		"host":          r.Host,
		"src_ip":        srcIP,
	})
}

// logNonInterruptTrace 在 debug 模式下输出未拦截事务的命中清单与 anomaly 分，供线下排查。
// 注：只有 debug 开关打开才会调用，热路径无开销。
func (w *WafOWASP) logNonInterruptTrace(tx types.Transaction) {
	matched := tx.MatchedRules()
	hits := make([]map[string]interface{}, 0, len(matched))
	for _, mr := range matched {
		if mr.Message() == "" {
			continue
		}
		rm := mr.Rule()
		hits = append(hits, map[string]interface{}{
			"id":       rm.ID(),
			"phase":    rm.Phase(),
			"severity": rm.Severity().String(),
			"msg":      mr.Message(),
		})
	}

	readInt := func(key string) int {
		if txState, ok := tx.(plugintypes.TransactionState); ok {
			if vals := txState.Variables().TX().Get(key); len(vals) > 0 {
				if v, err := strconv.Atoi(vals[0]); err == nil {
					return v
				}
			}
		}
		return 0
	}

	zlog.Debug("OWASP tx non-interrupt trace", map[string]interface{}{
		"matched_total":             len(hits),
		"matched":                   hits,
		"blocking_inbound_score":    readInt("blocking_inbound_anomaly_score"),
		"detection_inbound_score":   readInt("detection_inbound_anomaly_score"),
		"inbound_anomaly_score_pl1": readInt("inbound_anomaly_score_pl1"),
		"inbound_anomaly_score_pl2": readInt("inbound_anomaly_score_pl2"),
		"inbound_anomaly_threshold": readInt("inbound_anomaly_score_threshold"),
	})
}

// processConnection 处理连接信息
func (w *WafOWASP) processConnection(tx types.Transaction, weblog *innerbean.WebLog, r *http.Request) error {
	clientIP := ""
	if weblog != nil {
		clientIP = weblog.SRC_IP
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}
	}

	clientPort := 0
	if weblog != nil && weblog.SRC_PORT != "" {
		if port, err := strconv.Atoi(weblog.SRC_PORT); err == nil {
			clientPort = port
		}
	}

	// 获取服务器信息
	serverIP := "127.0.0.1"
	serverPort := 80

	if r.Host != "" {
		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			serverIP = host[:idx]
			if port, err := strconv.Atoi(host[idx+1:]); err == nil {
				serverPort = port
			}
		} else {
			serverIP = host
			if r.TLS != nil {
				serverPort = 443
			}
		}
	}

	tx.ProcessConnection(clientIP, clientPort, serverIP, serverPort)
	return nil
}

// processRequestLine 处理请求行
func (w *WafOWASP) processRequestLine(tx types.Transaction, r *http.Request) {
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = r.URL.Path
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}
	}
	tx.ProcessURI(uri, r.Method, r.Proto)
}

// processRequestHeaders 处理请求头
func (w *WafOWASP) processRequestHeaders(tx types.Transaction, r *http.Request) {
	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	if r.Host != "" && r.Header.Get("Host") == "" {
		tx.AddRequestHeader("Host", r.Host)
	}
}

// processRequestBody 处理请求体（流式，避免多份内存副本）
//
// 优化要点：
//   - weblog.BODY 非空时直接 strings.NewReader 零拷贝共享底层字符串（原实现 []byte(weblog.BODY) 会多分配一份）
//   - 从 r.Body 读取时用 io.LimitReader 封顶，最大 maxRequestBodyBytes，避免无限读
//   - 读到的字节复用给下游消费，原实现会让同一 body 同时存在 3 份（weblog 字符串 + []byte 副本 + coraza 内部缓冲）
func (w *WafOWASP) processRequestBody(tx types.Transaction, r *http.Request, weblog *innerbean.WebLog) error {
	// 优先使用上游已经读取好的 body，避免二次读 r.Body
	if weblog != nil && weblog.BODY != "" {
		// strings.NewReader 与底层字符串共享只读数据，零拷贝
		if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(weblog.BODY)); err != nil {
			return fmt.Errorf("failed to feed weblog body to coraza: %v", err)
		}
		return nil
	}

	if r.Body == nil {
		return nil
	}

	// 读取 r.Body 并封顶。LimitReader + 1 用于探测是否超限（coraza 自身也会按 SecRequestBodyLimit 截断）
	bufPtr := bodyBufferPool.Get().(*[]byte)
	buf := bytes.NewBuffer((*bufPtr)[:0])
	defer func() {
		// 回池前丢弃过大的 buffer，避免长期占用
		if cap(buf.Bytes()) <= 1<<20 { // 1MB
			*bufPtr = buf.Bytes()[:0]
			bodyBufferPool.Put(bufPtr)
		}
	}()

	_, err := io.Copy(buf, io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}

	data := buf.Bytes()
	// 重置 body 以便下游继续消费
	bodyCopy := make([]byte, len(data))
	copy(bodyCopy, data)
	r.Body = io.NopCloser(bytes.NewReader(bodyCopy))

	if len(bodyCopy) > 0 {
		if _, _, err := tx.WriteRequestBody(bodyCopy); err != nil {
			return fmt.Errorf("failed to write request body: %v", err)
		}
	}

	return nil
}

// handleInterruption 处理中断情况
//
// 热路径优化：
//   - 默认仅从 MatchedRules 提取最关键信息，strings.Builder 预分配
//   - 仅当 global.GWAF_LOG_DEBUG_ENABLE 为 true 时才去遍历 Variables().All() 收集完整上下文
//     （原实现每次命中都全量扫描所有 collection，成百上千次 map 分配压垮 GC）
func (w *WafOWASP) handleInterruption(tx types.Transaction, it *types.Interruption) (bool, *types.Interruption, error) {
	matched := tx.MatchedRules()

	// 不向上层暴露命中规则详情：it.Data 保持空，完整细节通过 zlog 记录。
	// 这样 checkowasp.go 拼出的 result.Title 只有 "OWASP:<ruleID>"，不会把规则消息泄漏给访客或塞满通知面板。
	if it != nil {
		it.Data = ""
	}

	// 命中统计：只记录有 message 的规则（排除 CRS 初始化类 SecAction，它们 message 为空）。
	for _, mr := range matched {
		rm := mr.Rule()
		if rm.ID() > 0 && mr.Message() != "" {
			GlobalHitStats.RecordBlocked(rm.ID(), mr.Message(), rm.Severity().String())
		}
	}

	// 慢路径：仅 debug 模式下采集完整上下文
	if debugEnabled.Load() {
		details := w.collectTransactionDetails(tx, matched)
		w.logger.Error("OWASP WAF Interruption", details)
	}

	return true, it, nil
}

// collectTransactionDetails 收集事务详细信息（仅 debug 模式调用）
func (w *WafOWASP) collectTransactionDetails(tx types.Transaction, matched []types.MatchedRule) map[string]interface{} {
	details := map[string]interface{}{
		"transaction_id": tx.ID(),
		"interrupted":    tx.IsInterrupted(),
	}

	// 匹配的规则信息
	matchedRules := make([]map[string]interface{}, 0, len(matched))
	for _, rule := range matched {
		if rule.Message() == "" {
			continue
		}
		matchedRules = append(matchedRules, map[string]interface{}{
			"id":      rule.Rule().ID(),
			"message": rule.Message(),
			"file":    rule.Rule().File(),
			"line":    rule.Rule().Line(),
		})
	}
	details["matched_rules"] = matchedRules
	details["rules_matched_total"] = len(matchedRules)

	// 变量信息：仅 debug 模式收集，在大请求下成本极高
	if txState, ok := tx.(plugintypes.TransactionState); ok {
		collections := []map[string]interface{}{}
		txState.Variables().All(func(_ variables.RuleVariable, v collection.Collection) bool {
			for index, md := range v.FindAll() {
				collections = append(collections, map[string]interface{}{
					"collection": v.Name(),
					"key":        md.Key(),
					"index":      index,
					"value":      md.Value(),
				})
			}
			return true
		})
		details["collections"] = collections
	}

	if it := tx.Interruption(); it != nil {
		details["interruption"] = map[string]interface{}{
			"action":  it.Action,
			"rule_id": it.RuleID,
			"status":  it.Status,
		}
	}

	return details
}

// 处理响应
func (w *WafOWASP) ProcessResponse(tx types.Transaction, statusCode int, headers http.Header, body []byte) (*types.Interruption, error) {
	if !w.IsActive {
		return nil, nil
	}

	for name, values := range headers {
		for _, value := range values {
			tx.AddResponseHeader(name, value)
		}
	}

	if it := tx.ProcessResponseHeaders(statusCode, "HTTP/1.1"); it != nil {
		return it, nil
	}

	if len(body) > 0 {
		if _, _, err := tx.WriteResponseBody(body); err != nil {
			return nil, fmt.Errorf("failed to write response body: %v", err)
		}
	}

	if it, err := tx.ProcessResponseBody(); err != nil {
		return nil, fmt.Errorf("response body processing error: %v", err)
	} else if it != nil {
		return it, nil
	}

	return nil, nil
}
