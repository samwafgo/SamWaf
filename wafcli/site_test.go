package wafcli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mockSites struct {
	sites  map[string]siteRecord
	writes int
	deny   bool
}

func (s *mockSites) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	send := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": data, "msg": "ok"}) }
	if s.deny {
		_ = json.NewEncoder(w).Encode(map[string]any{"code": -999, "data": "", "msg": "denied"})
		return
	}
	switch strings.TrimPrefix(r.URL.Path, hostAPI) {
	case "list":
		list := []siteRecord{}
		for _, v := range s.sites {
			list = append(list, v)
		}
		send(map[string]any{"list": list, "total": len(list)})
	case "detail":
		send(s.sites[r.URL.Query().Get("code")])
	case "add":
		var m siteRecord
		_ = json.NewDecoder(r.Body).Decode(&m)
		m["code"] = json.RawMessage(`"created-code"`)
		s.sites["created-code"] = m
		s.writes++
		send("created-code")
	case "edit":
		var m siteRecord
		_ = json.NewDecoder(r.Body).Decode(&m)
		s.sites[recordString(m, "code")] = m
		s.writes++
		send(nil)
	case "startstatus":
		m := s.sites[r.URL.Query().Get("code")]
		m["start_status"] = json.RawMessage(r.URL.Query().Get("start_status"))
		s.writes++
		send(nil)
	case "del":
		delete(s.sites, r.URL.Query().Get("code"))
		s.writes++
		send(nil)
	default:
		w.WriteHeader(404)
	}
}

func testCommand(t *testing.T, base, input string, args ...string) (int, map[string]any, string) {
	t.Helper()
	old := siteClientFactory
	siteClientFactory = func(wait time.Duration) (*apiClient, error) { return newAPIClient(base, "test-key", wait), nil }
	defer func() { siteClientFactory = old }()
	root := newRootCommand(Deps{})
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetIn(strings.NewReader(input))
	root.SetArgs(args)
	_, err := root.ExecuteC()
	code := 0
	if err != nil {
		code = errorCode(err)
		if !strings.Contains(err.Error(), errResultWritten.Error()) {
			printError(root, err, code)
		}
	}
	var result map[string]any
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatalf("invalid single JSON output %q: %v", out.String(), e)
	}
	return code, result, out.String()
}

func TestSiteWorkflow(t *testing.T) {
	m := &mockSites{sites: map[string]siteRecord{}}
	srv := httptest.NewServer(http.HandlerFunc(m.serve))
	defer srv.Close()
	in := `{"host":"www.example.com","port":18080,"remote_host":"http://127.0.0.1","remote_port":9112,"nickname":"keep"}`
	action := func(in string, want string) {
		t.Helper()
		code, res, _ := testCommand(t, srv.URL, in, "site", "apply", "-f", "-", "-o", "json")
		if code != 0 || res["results"].([]any)[0].(map[string]any)["action"] != want {
			t.Fatalf("code=%d result=%v", code, res)
		}
	}
	action(in, "created")
	action(in, "unchanged")
	if m.writes != 1 {
		t.Fatalf("repeat wrote %d times", m.writes)
	}
	action(`{"host":"www.example.com","port":18080,"remarks":"changed"}`, "updated")
	if recordString(m.sites["created-code"], "nickname") != "keep" {
		t.Fatal("partial apply erased nickname")
	}
	code, res, _ := testCommand(t, srv.URL, "", "site", "get", "created-code", "-o", "json")
	if code != 0 || res["site"].(map[string]any)["remarks"] != "changed" {
		t.Fatalf("get: %v", res)
	}
	for _, cmd := range []string{"stop", "stop", "start", "delete"} {
		code, _, _ := testCommand(t, srv.URL, "", "site", cmd, "www.example.com:18080", "-o", "json")
		if code != 0 {
			t.Fatalf("%s code %d", cmd, code)
		}
	}
	code, _, _ = testCommand(t, srv.URL, "", "site", "delete", "created-code", "-o", "json")
	if code != ExitNotFound {
		t.Fatalf("missing code=%d", code)
	}
	m.deny = true
	code, _, _ = testCommand(t, srv.URL, "", "site", "list", "-o", "json")
	if code != ExitAuth {
		t.Fatalf("auth code=%d", code)
	}
}

func TestBatchPreflight(t *testing.T) {
	m := &mockSites{sites: map[string]siteRecord{}}
	srv := httptest.NewServer(http.HandlerFunc(m.serve))
	defer srv.Close()
	for _, input := range []string{
		`[{"host":"a.example.com","port":18080,"remote_host":"http://127.0.0.1","remote_port":9112},{"code":"x","typo":1}]`,
		`[{"host":"a.example.com","port":18080,"remote_host":"http://127.0.0.1","remote_port":9112},{"host":"b.example.com","port":18081}]`,
	} {
		code, _, _ := testCommand(t, srv.URL, input, "site", "apply", "-f", "-", "-o", "json")
		if code != ExitUsage || m.writes != 0 {
			t.Fatalf("code=%d writes=%d", code, m.writes)
		}
	}
}

func TestClientBoundaries(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		hits := 0
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
		defer other.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
		defer srv.Close()
		a := newAPIClient(srv.URL, "test-key", 0)
		err := a.call(context.Background(), "GET", "/", nil, nil)
		if errorCode(err) != ExitFailed || hits != 0 {
			t.Fatalf("followed redirect: %v %d", err, hits)
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		base := srv.URL
		srv.Close()
		a := newAPIClient(base, "test-key", 0)
		if err := a.call(context.Background(), "GET", "/", nil, nil); errorCode(err) != ExitUnavailable {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tls", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"code":0,"data":{}}`)) }))
		defer srv.Close()
		a := newAPIClient(srv.URL, "test-key", 0)
		if err := a.call(context.Background(), "GET", "/", nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("proxy disabled", func(t *testing.T) {
		a := newAPIClient("http://127.0.0.1:26666", "test-key", 0)
		if a.http.Transport.(*http.Transport).Proxy != nil {
			t.Fatal("environment proxy is enabled")
		}
	})
}
