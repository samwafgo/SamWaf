package request

type WafHostGuardStatusReq struct {
	CODE         string `json:"code"`
	GUARD_STATUS int    `json:"guard_status"` //防御状态
}
