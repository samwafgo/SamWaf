package wafenginmodel

import (
	"SamWaf/model"
	"net/http"
)

// WebsiteDiagnosticSnapshot 是管理端诊断使用的运行配置副本。
type WebsiteDiagnosticSnapshot struct {
	Host        model.Hosts                   `json:"-"`
	TargetHost  string                        `json:"-"`
	Loaded      bool                          `json:"-"`
	MatchCode   string                        `json:"-"`
	MatchKind   string                        `json:"-"`
	Steps       []string                      `json:"-"`
	Mode        string                        `json:"-"`
	PathRule    *model.HostPathRule           `json:"-"`
	PathRules   []model.HostPathRule          `json:"-"`
	Backends    []model.LoadBalance           `json:"-"`
	OriginPlans []WebsiteDiagnosticOriginPlan `json:"-"`
	Limitations []string                      `json:"-"`
}

// WebsiteDiagnosticOriginPlan 只描述请求构造，不执行连接或选择负载后端。
type WebsiteDiagnosticOriginPlan struct {
	Kind               string      `json:"-"`
	Error              string      `json:"-"`
	BackendID          string      `json:"-"`
	URL                string      `json:"-"`
	Host               string      `json:"-"`
	Headers            http.Header `json:"-"`
	FixedAddress       string      `json:"-"`
	FallbackAddress    string      `json:"-"`
	ServerName         string      `json:"-"`
	InsecureSkipVerify bool        `json:"-"`
}
