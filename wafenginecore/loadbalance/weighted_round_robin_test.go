package loadbalance

import (
	"fmt"
	"testing"
)

func BenchmarkWeight(b *testing.B) {
	b.ReportAllocs()
	wrrB := &WeightRoundRobinBalance{}
	wrrB.Add(0, 5)
	wrrB.Add(1, 3)
	wrrB.Add(2, 2)
	// 创建一个 map 来存储每个地址的计数
	countMap := make(map[int]int)
	for i := 0; i < b.N; i++ {
		availableAddr, err := wrrB.Get()
		if err != nil {
			panic(err)
		}
		// 更新计数器
		countMap[availableAddr]++
		fmt.Printf("当前地址编号是:%d \n", availableAddr)
	}
	// 在 benchmark 完成后打印结果
	fmt.Println("Address counts:")
	total := b.N
	for addr, count := range countMap {
		percentage := float64(count) / float64(total) * 100
		fmt.Printf("地址 %d 出现了 %d 次，占比 %.2f%%\n", addr, count, percentage)
	}
	/**
	测试结果
	地址 0 出现了 186040 次，占比 50.00%
	地址 1 出现了 111624 次，占比 30.00%
	地址 2 出现了 74416 次，占比 20.00%

	**/
}
