package utils

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// PortCheck 检查端口是否可用，可用-true 不可用-false
func PortCheck(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%d", port), time.Second)
	if err != nil {
		return true // Port is available
	}
	defer conn.Close()
	return false // Port is not available
}

// TCP端口检测
func TCPPortCheck(port int) bool {
	conn, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	defer conn.Close()
	return false
}

// UDP端口检测
func UDPPortCheck(port int) bool {
	addr, _ := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(port))
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return true
	}
	defer conn.Close()
	return false
}
