package validfield

// IsValidHostFilterField 检测host字段是否合法
func IsValidHostFilterField(field string) bool {
	var allowedFilterFields = []string{"host", "port", "remote_ip", "remote_port", "remarks"}

	for _, allowedField := range allowedFilterFields {
		if field == allowedField {
			return true
		}
	}
	return false
}

// IsValidWebLogFilterField 检测log字段是否合法
func IsValidWebLogFilterField(field string) bool {
	var allowedFilterFields = []string{"header", "guest_identification"}

	for _, allowedField := range allowedFilterFields {
		if field == allowedField {
			return true
		}
	}
	return false
}
