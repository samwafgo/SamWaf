package wafcli

import (
	"encoding/json"
	"strings"
	"testing"
)

func siteJSON(s string) siteRecord {
	var m siteRecord
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		panic(err)
	}
	return m
}

func TestReadSiteInput(t *testing.T) {
	for _, tc := range []struct {
		name, s string
		count   int
	}{
		{"object", `{"host":"www.example.com","port":8080}`, 1},
		{"array", `[{"code":"x"},{"code":"y"}]`, 2},
		{"unknown", `{"code":"x","typo":1}`, 0},
		{"missing identity", `{"remarks":"hello"}`, 0},
		{"wrong type", `{"code":"x","port":"8080"}`, 0},
		{"null", `{"code":"x","remarks":null}`, 0},
		{"empty", `[]`, 0},
		{"trailing", `{"code":"x"} {"code":"y"}`, 0},
		{"secret", `{"code":"x","keyfile":"test-secret"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items, err := readSiteInput("-", strings.NewReader(tc.s))
			if tc.count == 0 {
				if err == nil || errorCode(err) != ExitUsage {
					t.Fatalf("expected usage error, got %v", err)
				}
				return
			}
			if err != nil || len(items) != tc.count {
				t.Fatalf("got %d items, %v", len(items), err)
			}
		})
	}
	_, err := readSiteInput("-", strings.NewReader(strings.Repeat(" ", maxInputBytes+1)))
	if err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestMergePreservesAndSkips(t *testing.T) {
	input := siteJSON(`{"host":"www.example.com","port":8080,"remote_host":"http://127.0.0.1","remote_port":9112,"nickname":"keep"}`)
	cur, _, err := mergeSite(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	cur["code"] = json.RawMessage(`"site-code"`)
	cur["port_listens_json"] = json.RawMessage(`"[{\"port\":8080,\"proto\":\"http\"}]"`)
	cur["keyfile"] = json.RawMessage(`"PRIVATE_TEST_VALUE"`)
	body, changed, err := mergeSite(cur, siteJSON(`{"code":"site-code","remarks":"changed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "remarks" {
		t.Fatalf("changes %v", changed)
	}
	for _, k := range []string{"nickname", "defense_json", "healthy_json", "keyfile"} {
		if string(body[k]) != string(cur[k]) {
			t.Fatalf("lost %s", k)
		}
	}
	if _, ok := body["port_listens_json"]; ok {
		t.Fatal("implicit port listens must be omitted")
	}
	_, changed, err = mergeSite(cur, input)
	if err != nil || len(changed) != 0 {
		t.Fatalf("not unchanged: %v %v", changed, err)
	}
	explicit := siteJSON(`{"code":"site-code","port_listens_json":""}`)
	body, _, err = mergeSite(cur, explicit)
	if err != nil || string(body["port_listens_json"]) != `""` {
		t.Fatalf("explicit empty lost: %v", err)
	}
	exported := filterEditable(cur, true)
	if _, ok := exported["keyfile"]; ok {
		t.Fatal("export contains keyfile")
	}
}

func TestValidateCreate(t *testing.T) {
	for _, s := range []string{
		`{"host":"www.example.com","port":8080}`,
		`{"host":"www.example.com","port":70000,"remote_host":"http://127.0.0.1","remote_port":80}`,
		`{"host":"www.example.com","port":8080,"remote_host":"ftp://127.0.0.1","remote_port":80}`,
	} {
		if _, _, err := mergeSite(nil, siteJSON(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}

func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		ref, code, host string
		port            int
	}{
		{"abc", "abc", "", 0}, {"www.example.com:8080", "", "www.example.com", 8080},
		{"www.example.com:abc", "www.example.com:abc", "", 0}, {"[::1]:8080", "", "::1", 8080},
	} {
		code, host, port, err := parseSiteRef(tc.ref)
		if err != nil || code != tc.code || host != tc.host || port != tc.port {
			t.Fatalf("parse %s: %s %s %d %v", tc.ref, code, host, port, err)
		}
	}
}
func TestCreateDefaultsValid(t *testing.T) {
	var defaults siteRecord
	if err := json.Unmarshal([]byte(createDefaultsJSON), &defaults); err != nil {
		t.Fatalf("create defaults: %v", err)
	}
	for _, key := range []string{"defense_json", "healthy_json", "captcha_json", "anti_leech_json", "cache_json", "response_compress_json", "cookie_security_json", "csrf_json", "access_json", "tamper_json", "upload_security_json", "static_site_json", "transport_json", "custom_headers_json"} {
		var value string
		if err := json.Unmarshal(defaults[key], &value); err != nil {
			t.Fatalf("%s outer: %v", key, err)
		}
		if !json.Valid([]byte(value)) {
			t.Fatalf("%s inner is not valid JSON", key)
		}
	}
}
