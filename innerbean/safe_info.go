package innerbean

type ISafeInfo interface {
}
type SafeInfo struct {
	ExecResult int
}
type CCInfo struct {
	SafeInfo
}

// 请求原始信息
type WAF_REQUEST_FULL struct {
	SRC_INFO   WebLog
	ExecResult int
}
