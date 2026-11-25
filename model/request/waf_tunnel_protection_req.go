package request

import "SamWaf/model"

type WafTunnelProtectionDetailReq struct {
	ID string `form:"id" binding:"required,max=64"`
}

type WafTunnelRegionProtectionReq struct {
	ID       string                   `json:"id" binding:"required,max=64"`
	Revision int64                    `json:"revision" binding:"gte=0"`
	Enabled  *bool                    `json:"enabled" binding:"required"`
	Fallback string                   `json:"fallback" binding:"required,oneof=allow deny"`
	Unknown  string                   `json:"unknown" binding:"required,oneof=allow deny"`
	Rules    []model.TunnelRegionRule `json:"rules" binding:"required,max=32"`
}

type WafTunnelDDNSProtectionReq struct {
	ID                      string                    `json:"id" binding:"required,max=64"`
	Revision                int64                     `json:"revision" binding:"gte=0"`
	Bindings                []model.TunnelDDNSBinding `json:"bindings" binding:"required,max=16"`
	ConfirmDisableWhitelist bool                      `json:"confirm_disable_whitelist"`
}

type WafTunnelDDNSRefreshReq struct {
	ID        string `json:"id" binding:"required,max=64"`
	BindingID string `json:"binding_id" binding:"required,max=64"`
}
