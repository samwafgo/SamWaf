package plugin

import (
	"sync"
	"time"
)

type IpRecord struct {
	IpCnt      int64
	Ip         string
	IpLockTime int64
}
type IpCounter struct {
	mu sync.Mutex
	v  map[string]*IpRecord
}

func (c *IpCounter) InitCounter() {
	c.v = map[string]*IpRecord{}
}

// Inc increments the counter for the given key.
func (c *IpCounter) Inc(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lock so only one goroutine at a time can access the map c.v.
	ipc := c.v[key]
	if ipc != nil {
		c.v[key].IpCnt += 1
	} else {
		c.v[key] = &IpRecord{
			IpCnt:      0,
			Ip:         key,
			IpLockTime: 0,
		}
	}
}

func (c *IpCounter) Lock(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lock so only one goroutine at a time can access the map c.v.
	ipc := c.v[key]
	if ipc != nil {
		c.v[key].IpLockTime = time.Now().Unix()
	}
}

func (c *IpCounter) UnLock(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Lock so only one goroutine at a time can access the map c.v.
	ipc := c.v[key]
	if ipc != nil {
		c.v[key].IpLockTime = 0
		c.v[key].IpCnt = 0
	}
}
func (c *IpCounter) Value(key string) *IpRecord {
	c.mu.Lock()
	// Lock so only one goroutine at a time can access the map c.v.
	defer c.mu.Unlock()
	return c.v[key]
}
