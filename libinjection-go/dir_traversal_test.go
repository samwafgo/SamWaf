package libinjection

import (
	"fmt"
	"testing"
)

func TestHasDirTraversal(t *testing.T) {
	// 测试用例
	testURLs := []string{
		"http://example.com/download?file=../../etc/passwd", // 应检测到
		"http://example.com/?id=../../../../etc/passwd",     // 应检测到
		"http://example.com/../../secret.txt",               // 应检测到
		"http://example.com/?path=%2e%2e%2fetc%2fpasswd",    // 应检测到（URL编码的../）
		"http://example.com/valid?file=doc.pdf",             // 正常URL
		"http://example.com/?data=..\\Windows\\system.ini",  // 检测Windows路径
	}

	for _, u := range testURLs {
		fmt.Printf("检测URL: %-50s => 存在漏洞: %t\n", u, HasDirTraversal(u))
	}
}
