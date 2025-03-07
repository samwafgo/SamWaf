package loadbalance

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// 生成随机的 IPv4 地址
func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(256), // 第一个字节
		rand.Intn(256), // 第二个字节
		rand.Intn(256), // 第三个字节
		rand.Intn(256)) // 第四个字节
}

func BenchmarkIpHash(b *testing.B) {
	b.ReportAllocs()
	hashBalance := NewConsistentHashBalance(nil, "")
	hashBalance.Add("0", 1) // 权重为10
	hashBalance.Add("1", 1) // 权重为5
	hashBalance.Add("2", 1) // 权重为1

	// 创建一个 map 来存储每个地址的计数
	countMap := make(map[string]int)
	rand.Seed(time.Now().UnixNano()) // 设置随机种子

	// 循环多次以触发不同的地址
	for i := 0; i < b.N; i++ {
		// 使用随机生成的 IP 地址作为键
		key := generateRandomIP()
		availableAddr, err := hashBalance.Get(key)
		if err != nil {
			b.Fatalf("Error getting address: %v", err)
		}
		// 更新计数器
		countMap[availableAddr]++
	}

	// 在 benchmark 完成后打印结果
	b.Log("Address counts:")
	total := b.N
	for addr, count := range countMap {
		percentage := float64(count) / float64(total) * 100
		b.Logf("地址 %s 出现了 %d 次，占比 %.2f%%\n", addr, count, percentage)
	}
}
