package wafcli

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnknownSiteSubcommandExitsUsage(t *testing.T) {
	var out bytes.Buffer
	root := newRootCommand(Deps{})
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"site", "unknown-command"})
	_, err := root.ExecuteC()
	if err == nil || errorCode(err) != ExitUsage {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("output=%s", out.String())
	}
}
