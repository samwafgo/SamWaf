package waflogexport

const narrowSchema = `
 req_uuid TEXT PRIMARY KEY, tenant_id TEXT, user_code TEXT, host_code TEXT, host TEXT,
 url TEXT, raw_query TEXT, method TEXT, scheme TEXT, referer TEXT, user_agent TEXT,
 src_ip TEXT, src_port TEXT, net_src_ip TEXT, country TEXT, province TEXT, city TEXT,
 action TEXT, rule TEXT, status TEXT, status_code INTEGER, risk_level INTEGER, ai_score REAL,
 is_bot INTEGER, log_only_mode INTEGER, guest_identification TEXT,
 time_spent INTEGER, content_length INTEGER, res_content_length INTEGER, pre_check_cost INTEGER,
 forward_cost INTEGER, backend_check_cost INTEGER, is_balance INTEGER, balance_info TEXT,
 body_hash TEXT, truncated INTEGER, actor_key TEXT, ua_hash TEXT, path_norm TEXT,
 create_time TEXT, unix_add_time INTEGER, day INTEGER`

var sqliteSchemas = map[string]string{
	"access_log":     "CREATE TABLE access_log (" + narrowSchema + ")",
	"security_event": "CREATE TABLE security_event (" + narrowSchema + ", payload_hash TEXT)",
}
var sqliteIndexes = map[string]string{
	"access_log":     "CREATE INDEX idx_export_al_time ON access_log(create_time, req_uuid)",
	"security_event": "CREATE INDEX idx_export_se_time ON security_event(create_time, req_uuid)",
}
