package validfield

// IsValidHostFilterField 检测host字段是否合法
func IsValidHostFilterField(field string) bool {
	var allowedFilterFields = []string{"host", "port", "remote_ip", "remote_port", "remarks", "nickname"}

	for _, allowedField := range allowedFilterFields {
		if field == allowedField {
			return true
		}
	}
	return false
}

// IsValidWebLogFilterField 检测log字段是否合法
func IsValidWebLogFilterField(field string) bool {
	// header=请求全文（仅安全事件视图，走报文子查询）；user_agent/referer 是窄行上的列，
	// 供访问日志视图替代 header 做筛选
	var allowedFilterFields = []string{"header", "guest_identification", "req_uuid", "user_agent", "referer"}

	for _, allowedField := range allowedFilterFields {
		if field == allowedField {
			return true
		}
	}
	return false
}
