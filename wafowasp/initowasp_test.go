package wafowasp

import (
	"fmt"
	"testing"
)

func TestOwasp(t *testing.T) {
	t.Skip("InitOwasp helper not implemented; integration test requires releasing data/owasp assets")
	owasp := NewWafOWASP(true, "..")
	if owasp == nil || owasp.WAF == nil {
		t.Skip("owasp data not released, skipping")
		return
	}
	tx := owasp.WAF.NewTransaction()
	defer tx.Close()

	tx.AddRequestHeader("Host", "www.demo1.com")
	tx.ProcessURI("/control/sqlinject/manifest_error.php?id=-1%27/*%2a%%2f*/union/*%2f%2f*//*!50144select*//*%2f%2f*/1,version()%23", "GET", "HTTP/1.1")

	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		fmt.Println(err)
	}
	if tx.IsInterrupted() {
		fmt.Println("interrupted")
	}
}

func TestWafOwasp(t *testing.T) {
}
