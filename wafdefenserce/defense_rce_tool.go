package wafdefenserce

import "strings"

func DetermineRCE(args ...string) (bool, string) {
	isRce, RceName := phpRCE(args...)
	if isRce == true {
		return isRce, RceName
	}
	return false, "未知"
}

/*
*
php rce检测
*/
func phpRCE(args ...string) (bool, string) {
	for _, arg := range args {
		if strings.Contains(arg, "phpinfo()") {
			return true, "存在PHP rce攻击"
		}
		if strings.Contains(arg, "call_user_func_array") {
			return true, "存在PHP rce攻击"
		}
		if strings.Contains(arg, "invokefunction") {
			return true, "存在PHP rce攻击"
		}
	}
	return false, "未知"
}
