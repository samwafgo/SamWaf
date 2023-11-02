package wafsnowflake

//雪花算法
import (
	"fmt"
	"sync"
	"time"
)

// Snowflake 结构
type Snowflake struct {
	mutex        sync.Mutex
	epoch        int64
	machineID    int64
	datacenterID int64
	sequence     int64
}

// NewSnowflake 创建一个 Snowflake 实例
func NewSnowflake(epoch, machineID, datacenterID int64) *Snowflake {
	return &Snowflake{
		epoch:        epoch,
		machineID:    machineID,
		datacenterID: datacenterID,
		sequence:     0,
	}
}

// NextID 生成下一个唯一ID 返回0 代表生成失败
func (s *Snowflake) NextID() int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	currentTime := time.Now().UnixNano() / 1000000 // 转换为毫秒
	if currentTime < s.epoch {
		fmt.Println("错误系统时间小于epoch时间")
		return 0
	}

	if currentTime == s.epoch {
		s.sequence++
	} else {
		s.sequence = 0
	}

	if s.sequence >= 4096 {
		fmt.Println("序列号溢出")
		return 0
	}

	ID := ((currentTime - s.epoch) << 22) | (s.datacenterID << 17) | (s.machineID << 12) | s.sequence
	return ID
}
