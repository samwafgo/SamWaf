package wafowasp

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// TestAnomalyScoreExtraction 跑一条实际的 SQLi 请求，验证 TransactionState 断言是否成功、
// 以及 blocking_inbound_anomaly_score / anomaly_score 等 TX 键是否有值。
func TestAnomalyScoreExtraction(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	owaspRoot := filepath.Join(repoRoot, "cmd", "samwaf", "exedata", "owasp")

	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(filepath.Join(owaspRoot, "coraza.conf")).
		WithDirectivesFromFile(filepath.Join(owaspRoot, "coreruleset", "crs-setup.conf"))

	rulesDir := filepath.Join(owaspRoot, "coreruleset", "rules")
	matches, _ := filepath.Glob(filepath.Join(rulesDir, "*.conf"))
	for _, p := range matches {
		cfg = cfg.WithDirectivesFromFile(p)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Skipf("skip: can't init waf: %v", err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 80)
	tx.ProcessURI("/index.php?id=1%20AND%201=1", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("User-Agent", "curl/7.88")

	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Logf("phase1 blocked by rule %d: %s", it.RuleID, it.Data)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process body: %v", err)
	}
	if it := tx.Interruption(); it != nil {
		t.Logf("blocked by rule %d action=%s data=%s", it.RuleID, it.Action, it.Data)
	} else {
		t.Logf("not blocked")
	}

	txState, ok := tx.(plugintypes.TransactionState)
	if !ok {
		t.Fatalf("transaction does NOT implement plugintypes.TransactionState - need alternative approach")
	}
	t.Logf("transaction implements TransactionState: OK")

	txCol := txState.Variables().TX()
	keys := []string{
		"blocking_inbound_anomaly_score",
		"inbound_anomaly_score",
		"blocking_anomaly_score",
		"anomaly_score",
		"inbound_anomaly_score_pl1",
		"inbound_anomaly_score_pl2",
		"critical_anomaly_score",
	}
	for _, k := range keys {
		vals := txCol.Get(k)
		t.Logf("tx:%s = %v", k, vals)
	}
	// Also dump keys with "anomaly" in name
	for _, md := range txCol.FindAll() {
		k := md.Key()
		if len(k) > 6 {
			t.Logf("ALL tx:%s = %s", k, md.Value())
		}
	}
}
