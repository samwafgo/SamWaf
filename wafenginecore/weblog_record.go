package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
)

// isURLLogExcluded 判断该 URL 是否命中站点配置的"排除记录"前缀列表
// excludeURLLog 为换行分隔的前缀列表；空行直接忽略（否则 HasPrefix(url,"") 恒为 true，
// 配置里多敲一个回车就会把整站日志全部吞掉）
func isURLLogExcluded(url string, excludeURLLog string) bool {
	if excludeURLLog == "" {
		return false
	}
	for _, line := range strings.Split(excludeURLLog, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(url, line) {
			return true
		}
	}
	return false
}

// shouldRecordWebLog 判断一条走完正常流程的访问日志该不该落库
//
// 记录类型 all：除排除前缀外全记。
// 记录类型 abnormal：除了非放行的请求，"命中了规则但没拦"的请求也必须留痕 ——
// 自定义规则放行/仅记录、站点仅记录模式(LogOnlyMode)、AI 观察命中，这些请求最终
// ACTION 都会被 modifyResponse 覆写成"放行"，若只看 ACTION 就会被整条丢弃，
// 导致白名单被谁用了、仅记录模式抓到了什么完全无法审计。
func shouldRecordWebLog(weblog *innerbean.WebLog, excludeURLLog string) bool {
	if weblog == nil {
		return false
	}
	if isURLLogExcluded(weblog.URL, excludeURLLog) {
		return false
	}
	switch global.GWAF_RUNTIME_RECORD_LOG_TYPE {
	case "all":
		return true
	case "abnormal":
		return weblog.ACTION != "放行" || weblog.RULE != "" || weblog.LogOnlyMode == 1
	}
	return false
}
