package api

import "testing"

// apply_method 是订单里唯一按取值分支判断的字段，写错不会在建单阶段暴露，
// 只会一路落库，直到 ACME 侧报 could not determine solvers。
func TestCheckApplyMethod(t *testing.T) {
	for _, ok := range []string{"http01", "dns01"} {
		if msg := checkApplyMethod(ok); msg != "" {
			t.Errorf("apply_method=%q 应被接受，实际报错：%s", ok, msg)
		}
	}
	// 早期文档把取值写成 http/dns，界面下拉的标签文本也容易被直接当值传进来
	for _, bad := range []string{"", "http", "dns", "HTTP01", "DNS01", "File Verification Method", "文件验证方式"} {
		if msg := checkApplyMethod(bad); msg == "" {
			t.Errorf("apply_method=%q 应被拒绝，实际被接受", bad)
		}
	}
}
