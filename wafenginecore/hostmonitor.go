package wafenginecore

import (
	"sync"
)

// 存储每个网站的活动连接数
var activeConnections = make(map[string]int)
var connectionLock sync.Mutex

// 存储每个网站的 QPS
var siteQPS = make(map[string]int)
var qpsLock sync.Mutex

// 增加活动连接数
func incrementActiveConnections(site string) {
	defer connectionLock.Unlock()
	connectionLock.Lock()
	activeConnections[site]++
}

// 减少活动连接数
func decrementActiveConnections(site string) {
	defer connectionLock.Unlock()
	connectionLock.Lock()
	// 检查当前值是否大于0，防止出现负数
	if activeConnections[site] > 0 {
		activeConnections[site]--
	}
}

// 增加 QPS 计数
func incrementQPS(site string) {
	defer qpsLock.Unlock()
	qpsLock.Lock()
	siteQPS[site]++
}

// 每秒重置 QPS 计数器
func ResetQPS() {
	qpsLock.Lock()
	for site := range siteQPS {
		siteQPS[site] = 0 // 重置为 0
	}
	qpsLock.Unlock()
}

// 获取某个网站的 QPS
func GetQPS(site string) int {
	qpsLock.Lock()
	defer qpsLock.Unlock()
	if qps, exists := siteQPS[site]; exists {
		return qps
	}
	return 0
}

// 获取某个网站的 当前活动连接
func GetActiveConnectCnt(site string) int {
	connectionLock.Lock()
	defer connectionLock.Unlock()
	if cnt, exists := activeConnections[site]; exists {
		return cnt
	}
	return 0
}

// 增加访问量
func incrementMonitor(hostcode string) {
	// 增加活动连接数
	incrementActiveConnections(hostcode)
	// 增加 QPS 计数
	incrementQPS(hostcode)
}

// 减少访问量
func decrementMonitor(hostcode string) {
	// 减少活动连接数
	decrementActiveConnections(hostcode)
}
