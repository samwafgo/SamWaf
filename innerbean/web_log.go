package innerbean

type WebLog struct {
	WafInnerDFlag string `json:"waf_inner_dflag"` //日志队列处理方式
	HOST          string `json:"host"`
	URL           string `json:"url"`
	REFERER       string `json:"referer"`
	USER_AGENT    string `json:"user_agent"`
	METHOD        string `json:"method"`
	HEADER        string `json:"header"`
	SRC_IP        string `json:"src_ip"`
	SRC_PORT      string `json:"src_port"`
	COUNTRY       string `json:"country"`
	PROVINCE      string `json:"province"`
	CITY          string `json:"city"`
	CREATE_TIME   string `gorm:"index:idx_weblog_time" json:"create_time"`
	//CREATE_TIME    string ` json:"create_time"`
	CONTENT_LENGTH int64  `json:"content_length"`
	COOKIES        string `json:"cookies"`
	BODY           string `json:"body"`
	REQ_UUID       string `json:"req_uuid"`
	USER_CODE      string `json:"user_code"`
	TenantId       string `json:"tenant_id"` //租户ID（主要键）
	HOST_CODE      string `json:"host_code"` //主机ID （主要键）
	Day            int    `json:"day"`       //日 （主要键）
	ACTION         string `json:"action"`
	RULE           string `json:"rule"`
	STATUS         string `json:"status"`      //状态
	STATUS_CODE    int    `json:"status_code"` //状态编码
	RES_BODY       string `json:"res_body"`    //返回信息
	POST_FORM      string `json:"post_form"`   //提交的表单数据
}
type WAFLog struct {
	REQ_UUID    string `json:"req_uuid"`
	ACTION      string `json:"action"`
	RULE        string `json:"rule"`
	CREATE_TIME string `json:"create_time"`
	USER_CODE   string `json:"user_code"`
}
