package cache

import (
	"sync"
	"time"
)

func InitWafOnlyLockWrite() WafOnlyLockWriteData {
	return WafOnlyLockWriteData{}
}

type WafOnlyLockWriteData struct {
	value int64
	mu    sync.RWMutex
}

func (d *WafOnlyLockWriteData) WriteData(val int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.value = val
}

func (d *WafOnlyLockWriteData) ReadData() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	time.Sleep(500 * time.Millisecond)
	return d.value
}
