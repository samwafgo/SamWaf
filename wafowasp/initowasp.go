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

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

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

// ProcessRequest 处理 HTTP 请求
func (w *WafOWASP) ProcessRequest(r *http.Request, weblog innerbean.WebLog) (bool, *types.Interruption, error) {
	if !w.IsActive {
		return false, nil, nil
	}

	tx := w.WAF.NewTransaction()
	defer func() {
		if err := tx.Close(); err != nil {
			w.logger.Error("Failed to close transaction", map[string]interface{}{"error": err.Error()})
		}
	}()

	// 1. 处理连接信息
	if err := w.processConnection(tx, weblog, r); err != nil {
		return false, nil, fmt.Errorf("connection processing error: %v", err)
	}

	// 2. 处理请求行
	if err := w.processRequestLine(tx, r); err != nil {
		return false, nil, fmt.Errorf("request line processing error: %v", err)
	}

	// 3. 处理请求头
	if err := w.processRequestHeaders(tx, r); err != nil {
		return false, nil, fmt.Errorf("request headers processing error: %v", err)
	}

	// 4. 检查请求头阶段的中断
	if it := tx.ProcessRequestHeaders(); it != nil {
		return w.handleInterruption(tx, it)
	}

	// 5. 处理请求体
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

	return false, nil, nil
}

// processConnection 处理连接信息
func (w *WafOWASP) processConnection(tx types.Transaction, weblog innerbean.WebLog, r *http.Request) error {
	clientIP := weblog.SRC_IP
	if clientIP == "" {
		clientIP = r.RemoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}
	}

	clientPort := 0
	if weblog.SRC_PORT != "" {
		if port, err := strconv.Atoi(weblog.SRC_PORT); err == nil {
			clientPort = port
		}
	}

	// 获取服务器信息
	serverIP := "127.0.0.1"
	serverPort := 80

	if r.Host != "" {
		host := r.Host
		if strings.Contains(host, ":") {
			parts := strings.Split(host, ":")
			if len(parts) == 2 {
				serverIP = parts[0]
				if port, err := strconv.Atoi(parts[1]); err == nil {
					serverPort = port
				}
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
func (w *WafOWASP) processRequestLine(tx types.Transaction, r *http.Request) error {
	// 构建完整的 URI
	uri := r.URL.RequestURI()
	if uri == "" {
		uri = r.URL.Path
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}
	}

	tx.ProcessURI(uri, r.Method, r.Proto)
	return nil
}

// processRequestHeaders 处理请求头
func (w *WafOWASP) processRequestHeaders(tx types.Transaction, r *http.Request) error {
	// 添加所有请求头
	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	// 确保 Host 头存在
	if r.Host != "" && r.Header.Get("Host") == "" {
		tx.AddRequestHeader("Host", r.Host)
	}

	return nil
}

// processRequestBody 处理请求体
func (w *WafOWASP) processRequestBody(tx types.Transaction, r *http.Request, weblog innerbean.WebLog) error {
	var bodyData []byte
	var err error

	// 优先使用 weblog 中的 BODY
	if weblog.BODY != "" {
		bodyData = []byte(weblog.BODY)
	} else if r.Body != nil {
		// 从请求中读取 body
		bodyData, err = io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %v", err)
		}
		// 重新设置 body，以便后续处理
		r.Body = io.NopCloser(bytes.NewReader(bodyData))
	}

	if len(bodyData) > 0 {
		// 写入请求体数据，让 Coraza 自动解析
		if _, _, err := tx.WriteRequestBody(bodyData); err != nil {
			return fmt.Errorf("failed to write request body: %v", err)
		}
	}

	return nil
}

// handleInterruption 处理中断情况
func (w *WafOWASP) handleInterruption(tx types.Transaction, it *types.Interruption) (bool, *types.Interruption, error) {
	// 收集详细信息用于日志记录
	details := w.collectTransactionDetails(tx)

	// 记录详细的日志信息
	w.logger.Error("OWASP WAF Interruption", details)

	// 将详细信息添加到中断对象中，以便返回给用户
	if it != nil {
		// 将匹配的规则信息转换为字符串
		var ruleDetails string
		if matchedRules, ok := details["matched_rules"].([]map[string]interface{}); ok && len(matchedRules) > 0 {
			for i, rule := range matchedRules {
				ruleDetails += fmt.Sprintf("规则ID: %v, 消息: %v", rule["id"], rule["message"])
				if i < len(matchedRules)-1 {
					ruleDetails += "\n"
				}
			}
			// 将规则详情添加到中断数据中
			it.Data = ruleDetails
		}
	}

	return true, it, nil
}

// collectTransactionDetails 收集事务详细信息
func (w *WafOWASP) collectTransactionDetails(tx types.Transaction) map[string]interface{} {
	details := map[string]interface{}{
		"transaction_id": tx.ID(),
		"interrupted":    tx.IsInterrupted(),
	}

	// 收集匹配的规则信息
	matchedRules := []map[string]interface{}{}
	for _, rule := range tx.MatchedRules() {
		if rule.Message() != "" {
			matchedRules = append(matchedRules, map[string]interface{}{
				"id":      rule.Rule().ID(),
				"message": rule.Message(),
				"file":    rule.Rule().File(),
				"line":    rule.Rule().Line(),
			})
		}
	}
	details["matched_rules"] = matchedRules
	details["rules_matched_total"] = len(matchedRules)

	// 收集变量信息（仅在需要时）
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

	// 收集中断信息
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

	// 添加响应头
	for name, values := range headers {
		for _, value := range values {
			tx.AddResponseHeader(name, value)
		}
	}

	// 处理响应头
	if it := tx.ProcessResponseHeaders(statusCode, "HTTP/1.1"); it != nil {
		return it, nil
	}

	// 写入响应体
	if len(body) > 0 {
		if _, _, err := tx.WriteResponseBody(body); err != nil {
			return nil, fmt.Errorf("failed to write response body: %v", err)
		}
	}

	// 处理响应体
	if it, err := tx.ProcessResponseBody(); err != nil {
		return nil, fmt.Errorf("response body processing error: %v", err)
	} else if it != nil {
		return it, nil
	}

	return nil, nil
}
