package request

import "SamWaf/model/common/request"

type WafAppAddReq struct {
	Code            string `json:"code"              form:"code"`
	Name            string `json:"name"              form:"name"              binding:"required,max=128"`
	AppDir          string `json:"app_dir"           form:"app_dir"           binding:"max=512"`
	StartCmd        string `json:"start_cmd"         form:"start_cmd"         binding:"required,max=1024"`
	Env             string `json:"env"               form:"env"               binding:"max=2048"`
	AutoStart       int    `json:"auto_start"        form:"auto_start"`
	StartStatus     int    `json:"start_status"      form:"start_status"`
	StopMode        string `json:"stop_mode"         form:"stop_mode"`
	StopCmd         string `json:"stop_cmd"          form:"stop_cmd"          binding:"max=1024"`
	StopTimeout     int    `json:"stop_timeout"      form:"stop_timeout"`
	RestartPolicy   string `json:"restart_policy"    form:"restart_policy"`
	RestartDelay    int    `json:"restart_delay"     form:"restart_delay"`
	MaxRestartCount int    `json:"max_restart_count" form:"max_restart_count"`
	LogMaxLines     int    `json:"log_max_lines"     form:"log_max_lines"`
	Remarks         string `json:"remarks"           form:"remarks"           binding:"max=512"`
}

type WafAppEditReq struct {
	Id string `json:"id"`
	WafAppAddReq
}

type WafAppDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafAppDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafAppSearchReq struct {
	request.PageInfo
}

type WafAppCodeReq struct {
	Code string `json:"code" form:"code"`
}

type WafAppRollbackReq struct {
	Code     string `json:"code"     form:"code"`
	Filename string `json:"filename" form:"filename"`
}

type WafAppChangeLogSearchReq struct {
	Code string `json:"code" form:"code" binding:"required"`
	request.PageInfo
}
