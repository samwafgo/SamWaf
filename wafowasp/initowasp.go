package wafowasp

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"encoding/json"
	"fmt"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"net/http"
	"strconv"
	"testing"
)

type WafOWASP struct {
	IsActive bool       // 是否激活 WAF
	WAF      coraza.WAF // 对 Coraza WAF 实例的引用
}

// InitOwasp 测试用
func InitOwasp(currentDir string) coraza.WAF {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(currentDir + "/data/owasp/coraza.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/crs-setup.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/rules/*.conf")

	// First we initialize our waf and our seclang parser
	wafOwasp, err := coraza.NewWAF(cfg)
	// Now we parse our rules
	if err != nil {
		fmt.Println(err)
	}
	return wafOwasp
}
func NewWafOWASP(isActive bool, currentDir string) *WafOWASP {
	// 初始化一个新的 WAF 实例
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(currentDir + "/data/owasp/coraza.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/crs-setup.conf").
		WithDirectivesFromFile(currentDir + "/data/owasp/coreruleset/rules/*.conf")

	// First we initialize our waf and our seclang parser
	waf, err := coraza.NewWAF(cfg)
	// Now we parse our rules
	if err != nil {
		fmt.Println(err)
	}
	return &WafOWASP{
		IsActive: isActive,
		WAF:      waf,
	}
}
func (w *WafOWASP) ProcessRequest(r *http.Request, weblog innerbean.WebLog) (bool, *types.Interruption, error) {
	// 只有在 WAF 激活时才处理请求
	if w.IsActive {
		tx := w.WAF.NewTransaction()
		defer tx.Close()

		// 添加请求头
		for key, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(key, value)
			}
		}
		// 添加请求行信息
		tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)

		// 如果有请求体，则读取并写入事务
		if weblog.BODY != "" {
			if _, _, err := tx.WriteRequestBody([]byte(weblog.BODY)); err != nil {
				return false, nil, fmt.Errorf("error writing request body: %v", err)
			}
		}
		// 处理请求头和请求体
		if it := tx.ProcessRequestHeaders(); it != nil {
			return false, nil, fmt.Errorf("error ProcessRequestHeaders: %v", it)
		}
		if _, err := tx.ProcessRequestBody(); err != nil {
			return false, nil, fmt.Errorf("request body processing error: %v", err)
		}
		interrupted := tx.IsInterrupted()
		if interrupted {
			//显示详细信息
			txState := tx.(plugintypes.TransactionState)
			collections := make([][]string, 0)
			// we transform this into collection, key, index, value
			txState.Variables().All(func(_ variables.RuleVariable, v collection.Collection) bool {
				for index, md := range v.FindAll() {
					collections = append(collections, []string{
						v.Name(),
						md.Key(),
						strconv.Itoa(index),
						md.Value(),
					})
				}
				return true
			})
			jsdata, err := json.Marshal(collections)
			if err != nil {
				fmt.Printf("Error marshaling %s\n", err)
			}
			md := [][]string{}
			for _, m := range tx.MatchedRules() {
				msg := m.Message()
				if msg == "" {
					continue
				}
				md = append(md, []string{strconv.Itoa(m.Rule().ID()), msg})
			}
			matchedData, err := json.Marshal(md)
			if err != nil {
				fmt.Printf("Error marshaling %s\n", err)
			}
			result := map[string]interface{}{
				"transaction_id":      tx.ID(),
				"collections":         string(jsdata),
				"matched_data":        string(matchedData),
				"rules_matched_total": strconv.Itoa(len(tx.MatchedRules())),
				"audit_log":           `{"error": "not implemented"}`,
				"disruptive_action":   "none",
				"disruptive_rule":     "-",
				"duration":            0,
			}
			zlog.Error("OWASP Detail", result)
			if it := tx.Interruption(); it != nil {
				result["disruptive_action"] = it.Action
				result["disruptive_rule"] = it.RuleID
			}
			return interrupted, tx.Interruption(), nil
		} else {
			return interrupted, nil, fmt.Errorf("request body processing error: %v")
		}
	}
	return false, nil, fmt.Errorf("error")
}

type testLogOutput struct {
	t *testing.T
}

func (l testLogOutput) Write(p []byte) (int, error) {
	fmt.Println(string(p))
	return len(p), nil
}
