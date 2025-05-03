package utils

import (
	"fmt"
	"net"
	"time"
)

// CheckPortReady 测试端口可用性
func CheckPortReady(port int, timeout time.Duration) bool {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}
