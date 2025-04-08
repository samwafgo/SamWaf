package uuid

import (
	"fmt"
	"sync"
	"testing"
)

func TestGenUUIDConcurrent(t *testing.T) {
	// 测试并发情况下生成的 UUID 是否唯一
	const goroutines = 10
	const countPerGoroutine = 1000

	var wg sync.WaitGroup
	uuidChan := make(chan string, goroutines*countPerGoroutine)

	// 并发生成 UUID
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < countPerGoroutine; j++ {
				uuidChan <- GenUUID()
			}
		}()
	}

	wg.Wait()
	close(uuidChan)

	// 检查是否有重复
	uuids := make(map[string]bool)
	for uuid := range uuidChan {
		if uuids[uuid] {
			t.Errorf("并发测试中发现重复 UUID: %s", uuid)
		}
		uuids[uuid] = true
	}
}

func BenchmarkGenUUID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenUUID()
	}
}

func TestGenUUIDList(t *testing.T) {
	for i := 0; i < 100; i++ {
		// 测试单次生成的 UUID 是否有效
		uuid := GenUUID()

		fmt.Println(fmt.Sprintf("uuidNew:%s", uuid))
	}

}
