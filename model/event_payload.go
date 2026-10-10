package model

// EventPayload 一条请求的报文，与 web_logs 按 req_uuid 一对一。
//
// 拆出来是因为 web_logs 一张表同时承担了「列表翻页」「按 IP/规则检索」「统计扫描」「看报文」四件事，
// 而报文列（header/cookies/body/res_body/post_form/res_header + 原始字节）占了绝大部分体积。
// 列表和统计从不读它们，却要把它们一起拖过磁盘。拆开后 web_logs 只剩窄列，报文按主键点查。
//
// Kind 预留给后续的分层写入：
//   - event  命中规则的请求（默认，也是当前唯一在写的值）
//   - sample 放行请求里被蓄水池采到的负样本（供 AI 训练）
//   - watch  观察名单内 IP 的全量留痕
type EventPayload struct {
	ReqUUID  string `gorm:"column:req_uuid;size:64;primaryKey" json:"req_uuid"`
	TenantId string `gorm:"size:64" json:"tenant_id"`
	UserCode string `gorm:"size:64" json:"user_code"`
	HostCode string `gorm:"size:64" json:"host_code"`
	Kind     string `gorm:"size:16" json:"kind"`

	HEADER    string `gorm:"type:text" json:"header"`
	COOKIES   string `gorm:"type:text" json:"cookies"`
	BODY      string `gorm:"type:text" json:"body"`
	RES_BODY  string `gorm:"type:text" json:"res_body"`
	POST_FORM string `gorm:"type:text" json:"post_form"`
	ResHeader string `gorm:"type:text" json:"res_header"`

	SrcByteBody    []byte `json:"src_byte_body"`
	SrcByteResBody []byte `json:"src_byte_res_body"`
	SrcURL         []byte `json:"src_url"`

	// Truncated 与 web_logs 上的同名列一致：单列超过上限被截断时为 1。
	Truncated int `json:"truncated"`

	// CreateTime 与 web_logs.create_time 同格式同值，保留期清理按它删，不必回表。
	CreateTime  string `gorm:"size:32;index:idx_ep_create_time" json:"create_time"`
	UnixAddTime int64  `json:"unix_add_time"`
	Day         int    `json:"day"`
}

// EventPayloadTableName 实时报文表名。归档分片上是它加分片后缀（见 wafdb.ResolveLogTables）。
const EventPayloadTableName = "event_payload"

func (EventPayload) TableName() string {
	return EventPayloadTableName
}

// 报文列全空的请求不值得占一行（比如被提前拦下、连 header 都没读到的连接）。
func (e *EventPayload) IsEmpty() bool {
	return e.HEADER == "" && e.COOKIES == "" && e.BODY == "" &&
		e.RES_BODY == "" && e.POST_FORM == "" && e.ResHeader == "" &&
		len(e.SrcByteBody) == 0 && len(e.SrcByteResBody) == 0 && len(e.SrcURL) == 0
}
