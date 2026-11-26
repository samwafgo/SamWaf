package wafcli

import (
	"encoding/json"
	"testing"

	"SamWaf/model"
)

func TestCreateDefaultsStaticSiteMatchesEngine(t *testing.T) {
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(createDefaultsJSON), &body); err != nil {
		t.Fatalf("createDefaultsJSON: %v", err)
	}
	raw, _ := body["static_site_json"].(string)
	var cfg model.StaticSiteConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("static_site_json: %v", err)
	}
	checks := map[string][2]string{
		"sensitive_paths":      {cfg.SensitivePaths, model.StaticSiteDefaultSensitivePaths},
		"sensitive_extensions": {cfg.SensitiveExtensions, model.StaticSiteDefaultSensitiveExtensions},
		"allowed_extensions":   {cfg.AllowedExtensions, model.StaticSiteDefaultAllowedExtensions},
		"sensitive_patterns":   {cfg.SensitivePatterns, model.StaticSiteDefaultSensitivePatterns},
	}
	for name, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s differs from engine default:\n got  %q\n want %q", name, v[0], v[1])
		}
	}
	if cfg.IsEnableStaticSite != 0 || cfg.StaticSitePath != "" {
		t.Errorf("static site must default to disabled with empty path")
	}
}
