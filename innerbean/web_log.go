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
	CREATE_TIME    string `json:"create_time"`
	CONTENT_LENGTH int64  `json:"content_length"`
	COOKIES        string `json:"cookies"`
	BODY           string `json:"body"`
}