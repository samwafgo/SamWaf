package request

type WebsiteDiagnosticHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WafHostDiagnosticReq struct {
	HostCode          string                    `json:"host_code"`
	Phase             string                    `json:"phase"`
	VisitorURL        string                    `json:"visitor_url"`
	Method            string                    `json:"method"`
	Headers           []WebsiteDiagnosticHeader `json:"headers"`
	UseSystemProxy    bool                      `json:"use_system_proxy"`
	ConfigFingerprint string                    `json:"config_fingerprint"`
	OriginCursor      int                       `json:"origin_cursor"`
}
