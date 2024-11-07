package wafhttpcore

import (
	"SamWaf/common/zlog"
	"net/url"
	"strings"
)

// 逆向编码处理
func WafHttpCoreUrlEncode(encoded string, maxDepth int) string {
	// 如果没有编码格式，直接返回
	if !strings.Contains(encoded, "%") {
		return encoded
	}

	// 限制递归的最大深度，防止无限递归
	if maxDepth <= 0 {
		return encoded // 达到最大递归深度时返回原始字符串
	}
	// 尝试解码 URL 编码
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		zlog.Error("URL_ENCODE 解码失败,尝试用Php解码", err.Error(), encoded)
		//尝试进行PHP解码
		return phpUrlEncode(encoded)
	}

	// 如果解码后结果与原值不同，则继续递归解码
	if decoded != encoded {
		// 递归解码并减少深度
		return WafHttpCoreUrlEncode(decoded, maxDepth-1)
	}

	// 否则直接返回解码后的值
	return decoded
}
