package response

type WebsiteDiagnosticField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type WebsiteDiagnosticAdvice struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Tab     string `json:"tab"`
	Section string `json:"section"`
}

type WebsiteDiagnosticCheck struct {
	ID            string                    `json:"id"`
	Title         string                    `json:"title"`
	Status        string                    `json:"status"`
	Reason        string                    `json:"reason"`
	Message       string                    `json:"message"`
	Overview      []WebsiteDiagnosticField  `json:"overview"`
	Request       string                    `json:"request"`
	Response      string                    `json:"response"`
	Connection    []WebsiteDiagnosticField  `json:"connection"`
	Advice        []WebsiteDiagnosticAdvice `json:"advice"`
	StatusCode    int                       `json:"status_code"`
	BodyTruncated bool                      `json:"body_truncated"`
}

type WebsiteDiagnosticSite struct {
	HostCode   string `json:"host_code"`
	Title      string `json:"title"`
	VisitorURL string `json:"visitor_url"`
}

type WafHostDiagnosticResponse struct {
	Phase             string                   `json:"phase"`
	ConfigFingerprint string                   `json:"config_fingerprint"`
	Site              WebsiteDiagnosticSite    `json:"site"`
	Checks            []WebsiteDiagnosticCheck `json:"checks"`
	NextCursor        int                      `json:"next_cursor"`
	HasMore           bool                     `json:"has_more"`
	Total             int                      `json:"total"`
	ErrorCode         string                   `json:"error_code,omitempty"`
}
