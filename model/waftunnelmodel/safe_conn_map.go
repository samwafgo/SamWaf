package waftunnelmodel

import (
	"net"
	"sync"
	"time"
)

// 连接类型常量
const (
	ConnTypeSource = iota // 来源连接（客户端连接）
	ConnTypeTarget        // 目标连接（服务器连接）
)

// ConnInfo 连接信息结构体
type ConnInfo struct {
	ConnType   int       // 连接类型：0-来源连接，1-目标连接
	CreateTime time.Time // 连接创建时间
}

// SafeTCPConnMap 线程安全的TCP连接管理Map
type SafeTCPConnMap struct {
	mu    sync.RWMutex
	items map[int]map[net.Conn]ConnInfo // 端口号 -> 连接 -> 连接信息
}

// NewSafeTCPConnMap 创建新的TCP连接安全Map
func NewSafeTCPConnMap() *SafeTCPConnMap {
	return &SafeTCPConnMap{
		items: make(map[int]map[net.Conn]ConnInfo),
	}
}

// AddConn 添加连接
func (m *SafeTCPConnMap) AddConn(port int, conn net.Conn, connType int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.items[port]; !exists {
		m.items[port] = make(map[net.Conn]ConnInfo)
	}

	m.items[port][conn] = ConnInfo{
		ConnType:   connType,
		CreateTime: time.Now(),
	}
}

// RemoveConn 移除连接
func (m *SafeTCPConnMap) RemoveConn(port int, conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conns, exists := m.items[port]; exists {
		delete(conns, conn)
	}
}

// ClosePortConns 关闭指定端口的所有连接
func (m *SafeTCPConnMap) ClosePortConns(port int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conns, exists := m.items[port]; exists {
		for conn := range conns {
			conn.Close()
		}
		delete(m.items, port)
	}
}

// CloseAllConns 关闭所有连接
func (m *SafeTCPConnMap) CloseAllConns() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, conns := range m.items {
		for conn := range conns {
			conn.Close()
		}
	}

	// 清空map
	m.items = make(map[int]map[net.Conn]ConnInfo)
}

// GetPortConnsCount 获取指定端口的连接数
func (m *SafeTCPConnMap) GetPortConnsCount(port int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if conns, exists := m.items[port]; exists {
		return len(conns)
	}
	return 0
}

// GetPortConnsCountByType 获取指定端口指定类型的连接数
func (m *SafeTCPConnMap) GetPortConnsCountByType(port int, connType int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	if conns, exists := m.items[port]; exists {
		for _, info := range conns {
			if info.ConnType == connType {
				count++
			}
		}
	}
	return count
}

// GetAllConnsCount 获取所有连接数
func (m *SafeTCPConnMap) GetAllConnsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, conns := range m.items {
		total += len(conns)
	}
	return total
}

// GetAllConnsCountByType 获取所有指定类型的连接数
func (m *SafeTCPConnMap) GetAllConnsCountByType(connType int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, conns := range m.items {
		for _, info := range conns {
			if info.ConnType == connType {
				total++
			}
		}
	}
	return total
}

// SafeUDPConnMap 线程安全的UDP连接管理Map
type SafeUDPConnMap struct {
	mu    sync.RWMutex
	items map[int]map[*net.UDPConn]ConnInfo // 端口号 -> 连接 -> 连接信息
}

// NewSafeUDPConnMap 创建新的UDP连接安全Map
func NewSafeUDPConnMap() *SafeUDPConnMap {
	return &SafeUDPConnMap{
		items: make(map[int]map[*net.UDPConn]ConnInfo),
	}
}

// AddConn 添加连接
func (m *SafeUDPConnMap) AddConn(port int, conn *net.UDPConn, connType int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.items[port]; !exists {
		m.items[port] = make(map[*net.UDPConn]ConnInfo)
	}

	m.items[port][conn] = ConnInfo{
		ConnType:   connType,
		CreateTime: time.Now(),
	}
}

// RemoveConn 移除连接
func (m *SafeUDPConnMap) RemoveConn(port int, conn *net.UDPConn) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conns, exists := m.items[port]; exists {
		delete(conns, conn)
	}
}

// ClosePortConns 关闭指定端口的所有连接
func (m *SafeUDPConnMap) ClosePortConns(port int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if conns, exists := m.items[port]; exists {
		for conn := range conns {
			conn.Close()
		}
		delete(m.items, port)
	}
}

// CloseAllConns 关闭所有连接
func (m *SafeUDPConnMap) CloseAllConns() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, conns := range m.items {
		for conn := range conns {
			conn.Close()
		}
	}

	// 清空map
	m.items = make(map[int]map[*net.UDPConn]ConnInfo)
}

// GetPortConnsCount 获取指定端口的连接数
func (m *SafeUDPConnMap) GetPortConnsCount(port int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if conns, exists := m.items[port]; exists {
		return len(conns)
	}
	return 0
}

// GetPortConnsCountByType 获取指定端口指定类型的连接数
func (m *SafeUDPConnMap) GetPortConnsCountByType(port int, connType int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	if conns, exists := m.items[port]; exists {
		for _, info := range conns {
			if info.ConnType == connType {
				count++
			}
		}
	}
	return count
}

// GetAllConnsCount 获取所有连接数
func (m *SafeUDPConnMap) GetAllConnsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, conns := range m.items {
		total += len(conns)
	}
	return total
}

// GetAllConnsCountByType 获取所有指定类型的连接数
func (m *SafeUDPConnMap) GetAllConnsCountByType(connType int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := 0
	for _, conns := range m.items {
		for _, info := range conns {
			if info.ConnType == connType {
				total++
			}
		}
	}
	return total
}

// GetPortConnsInfo 获取指定端口的连接信息
func (m *SafeTCPConnMap) GetPortConnsInfo(port int, connType int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ipList := make([]string, 0)
	if conns, exists := m.items[port]; exists {
		for conn, info := range conns {
			if info.ConnType == connType {
				// 获取连接的远程地址
				if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
					// 从地址中提取IP（去除端口）
					host, _, err := net.SplitHostPort(remoteAddr.String())
					if err == nil {
						ipList = append(ipList, host)
					} else {
						// 如果解析失败，使用原始地址
						ipList = append(ipList, remoteAddr.String())
					}
				}
			}
		}
	}
	return ipList
}

// GetPortConnsInfo 获取指定端口的连接信息
func (m *SafeUDPConnMap) GetPortConnsInfo(port int, connType int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ipList := make([]string, 0)
	if conns, exists := m.items[port]; exists {
		for conn, info := range conns {
			if info.ConnType == connType {
				// 获取连接的远程地址
				if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
					// 从地址中提取IP（去除端口）
					host, _, err := net.SplitHostPort(remoteAddr.String())
					if err == nil {
						ipList = append(ipList, host)
					} else {
						// 如果解析失败，使用原始地址
						ipList = append(ipList, remoteAddr.String())
					}
				}
			}
		}
	}
	return ipList
}
