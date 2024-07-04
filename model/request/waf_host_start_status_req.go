package request

type WafHostStartStatusReq struct {
	CODE         string `json:"code"`
	START_STATUS int    `json:"start_status"` //启动状态
}
