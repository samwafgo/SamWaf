package wafowasp

import (
	"strings"
	"testing"
)

func TestParseRules_Basic(t *testing.T) {
	raw := `# comment
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

SecAction \
    "id:900110,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.9.0-dev',\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"

SecRule &TX:crs_setup_version "@eq 0" \
    "id:901001,\
    phase:1,\
    deny,\
    status:500,\
    msg:'Hello it\\'s broken',\
    tag:'OWASP_CRS',\
    tag:'paranoia-level/2',\
    severity:'CRITICAL'"
`

	got, err := parseRules(strings.NewReader(raw), "test.conf")
	if err != nil {
		t.Fatalf("parseRules error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(got))
	}

	if got[0].ID != 200001 || got[0].Phase != 1 || got[0].Directive != "SecRule" {
		t.Errorf("rule0 mismatch: %+v", got[0])
	}
	if got[1].ID != 900110 || got[1].Directive != "SecAction" {
		t.Errorf("rule1 mismatch: %+v", got[1])
	}
	if got[2].ID != 901001 || got[2].Severity != "CRITICAL" || got[2].Paranoia != 2 {
		t.Errorf("rule2 mismatch: %+v", got[2])
	}
	if got[2].Message == "" || !strings.Contains(got[2].Message, "Hello") {
		t.Errorf("rule2 msg not extracted: %q", got[2].Message)
	}
	if len(got[2].Tags) != 2 {
		t.Errorf("rule2 tags expected 2 got %v", got[2].Tags)
	}
}

func TestParseRules_EmptyFile(t *testing.T) {
	got, err := parseRules(strings.NewReader("# just a comment\n"), "empty.conf")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(got))
	}
}
