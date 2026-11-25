package model

type TunnelRegionProtection struct {
	Revision int64              `json:"revision"`
	Enabled  bool               `json:"enabled"`
	Fallback string             `json:"fallback"`
	Unknown  string             `json:"unknown"`
	Rules    []TunnelRegionRule `json:"rules"`
}

type TunnelRegionRule struct {
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Country  string `json:"country"`
	Action   string `json:"action"`
	Enabled  bool   `json:"enabled"`
}

type TunnelDDNSProtection struct {
	Revision int64               `json:"revision"`
	Bindings []TunnelDDNSBinding `json:"bindings"`
}

type TunnelDDNSBinding struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Family  string `json:"family"`
	Enabled bool   `json:"enabled"`
}

type TunnelDDNSStatus struct {
	BindingID  string                   `json:"binding_id"`
	State      string                   `json:"state"`
	LastCheck  string                   `json:"last_check"`
	ValidUntil string                   `json:"valid_until"`
	Error      string                   `json:"error"`
	IPs        []string                 `json:"ips"`
	Families   []TunnelDDNSFamilyStatus `json:"families,omitempty"`
}

type TunnelDDNSFamilyStatus struct {
	Family     string   `json:"family"`
	State      string   `json:"state"`
	LastCheck  string   `json:"last_check"`
	ValidUntil string   `json:"valid_until"`
	Error      string   `json:"error"`
	IPs        []string `json:"ips"`
}
