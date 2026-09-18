package model

// LogNarrow 一条请求的窄行字段集，access_log 与 security_event 共用（gorm 嵌入展开）。
//
// 窄行的取舍：列表翻页、按 IP/规则/时间检索、统计扫描、bot 分析、CC 阈值推荐要用的列都在；
// 报文列（header/cookies/body/res_body/post_form/res_header 与原始字节）一律不在——
// 报文只跟「有报文的行」走，按 req_uuid 去 event_payload 点查。
// url/raw_query 落库前截断到 2KB（wafqueue 侧动手），超出置 Truncated=1。
//
// 三个分析键（actor_key/ua_hash/path_norm）必须在建表时就位：事后补列等于没有历史数据。
type LogNarrow struct {
	ReqUUID  string `gorm:"column:req_uuid;size:64;primaryKey" json:"req_uuid"`
	TenantId string `gorm:"size:64" json:"tenant_id"`
	UserCode string `gorm:"size:64" json:"user_code"`
	HostCode string `gorm:"size:64" json:"host_code"`
	Host     string `gorm:"size:255" json:"host"`

	URL        string `gorm:"size:2048" json:"url"`
	RawQuery   string `gorm:"size:2048" json:"raw_query"`
	Method     string `gorm:"size:20" json:"method"`
	Scheme     string `gorm:"size:20" json:"scheme"`
	REFERER    string `gorm:"size:1024" json:"referer"`
	USER_AGENT string `gorm:"size:500" json:"user_agent"`

	SRC_IP   string `gorm:"size:64" json:"src_ip"`
	SRC_PORT string `gorm:"size:10" json:"src_port"`
	NetSrcIp string `gorm:"size:64" json:"net_src_ip"` // CC 阈值推荐在站点 IPMode=网卡时只认这一列
	COUNTRY  string `gorm:"size:100" json:"country"`
	PROVINCE string `gorm:"size:100" json:"province"`
	CITY     string `gorm:"size:100" json:"city"`

	ACTION             string `gorm:"size:100" json:"action"`
	RULE               string `gorm:"type:text" json:"rule"`
	STATUS             string `gorm:"size:50" json:"status"`
	STATUS_CODE        int    `json:"status_code"`
	RISK_LEVEL         int    `json:"risk_level"`
	AI_SCORE           float64 `json:"ai_score"`
	IsBot              int    `json:"is_bot"`
	LogOnlyMode        int    `json:"log_only_mode"`
	GUEST_IDENTIFICATION string `gorm:"column:guest_id_entification;size:191" json:"guest_identification"`

	TimeSpent        int64  `json:"time_spent"`
	CONTENT_LENGTH   int64  `json:"content_length"`
	ResContentLength int64  `json:"res_content_length"`
	PreCheckCost     int64  `json:"pre_check_cost"`
	ForwardCost      int64  `json:"forward_cost"`
	BackendCheckCost int64  `json:"backend_check_cost"`

	IsBalance   int    `json:"is_balance"`
	BalanceInfo string `gorm:"size:255" json:"balance_info"`
	BodyHash    string `gorm:"size:100" json:"body_hash"`

	// Truncated：url/raw_query 超 2KB 被截断时置 1（报文截断只看 event_payload 里的同名列）。
	Truncated int `json:"truncated"`

	// 分析键（M5 汇总与 facet 的数据地基，写入时算好）。
	// actor_key 的索引不在 tag 里建：LogNarrow 同时嵌进 access_log 与 security_event，
	// 而 SQLite/PG 的索引名全库唯一，同名会撞——改在迁移里按表各建各的（idx_al_actor/idx_se_actor）。
	ActorKey string `gorm:"size:100" json:"actor_key"` // 访客身份优先，其次 IP
	UaHash   string `gorm:"size:64" json:"ua_hash"`                       // UA 指纹，供「同一人多少种 UA」
	PathNorm string `gorm:"size:512" json:"path_norm"`                    // 路径模板：数字段/UUID/hex 归一

	CREATE_TIME   string `gorm:"size:32" json:"create_time"`
	UNIX_ADD_TIME int64  `json:"unix_add_time"`
	Day           int    `json:"day"`
}

// AccessLogTableName 实时访问日志窄行表名。归档分片上是它加分片后缀。
const AccessLogTableName = "access_log"

// AccessLog 所有被记录请求的窄行（命中的请求也双写一份，访问日志页因此不需要 UNION）。
// 写多少由 access_log_mode 档位决定：db=全量，sample=事件+采样，off=仅事件。
// 保留期短（默认 30 天，access_log_retention_days）。
type AccessLog struct {
	LogNarrow `gorm:"embedded"`
}

func (AccessLog) TableName() string {
	return AccessLogTableName
}

// SecurityEventTableName 实时安全事件表名。归档分片上是它加分片后缀。
const SecurityEventTableName = "security_event"

// SecurityEvent 命中规则/被拦截/仅记录的请求（innerbean.WebLog.IsSecurityEvent 为真）。
// 报文一对一放 event_payload(kind=event)，按 req_uuid 点查。保留期长（随日志保留天数，默认 180 天）。
//
// PayloadHash 是本表独有的第四个键：规则 + 归一化命中内容指纹，
// 「同 hash 跨多个 IP」即分布式同一手法（M5 的聚类视图靠它）。
type SecurityEvent struct {
	LogNarrow   `gorm:"embedded"`
	PayloadHash string `gorm:"size:64" json:"payload_hash"`
}

func (SecurityEvent) TableName() string {
	return SecurityEventTableName
}
