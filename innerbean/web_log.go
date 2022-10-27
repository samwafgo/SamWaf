package innerbean

type WebLog struct {
	HOST           string `json:"host"`
	URL            string `json:"url"`
	REFERER        string `json:"referer"`
	USER_AGENT     string `json:"user_agent"`
	METHOD         string `json:"method"`
	HEADER         string `json:"header"`
	SRC_IP         string `json:"src_ip"`
	SRC_PORT       string `json:"src_port"`
	COUNTRY        string `json:"country"`
	PROVINCE       string `json:"province"`
	CITY           string `json:"city"`
	CREATE_TIME    string `json:"create_time"`
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
}
type WAFLog struct {
	REQ_UUID    string `json:"req_uuid"`
	ACTION      string `json:"action"`
	RULE        string `json:"rule"`
	CREATE_TIME string `json:"create_time"`
	USER_CODE   string `json:"user_code"`
}
