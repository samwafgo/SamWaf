package loadbalance

import (
	"errors"
	"hash/crc32"
	"sort"
	"strconv"
	"sync"
)

type Hash func(data []byte) uint32

type UInt32Slice []uint32

func (s UInt32Slice) Len() int {
	return len(s)
}

func (s UInt32Slice) Less(i, j int) bool {
	return s[i] < s[j] // 升序排列
}

func (s UInt32Slice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i] // 交换元素
}

type ConsistentHashBalance struct {
	mux     sync.RWMutex
	hash    Hash
	keys    UInt32Slice // 已排序的节点 hash 切片
	hashMap map[uint32]string
}

// 创建一个一致性哈希算法
func NewConsistentHashBalance(fn Hash) *ConsistentHashBalance {
	m := &ConsistentHashBalance{
		hash:    fn,
		hashMap: make(map[uint32]string),
	}
	if m.hash == nil {
		m.hash = crc32.ChecksumIEEE
	}
	return m
}

// 修改 Add 方法以接受权重
func (c *ConsistentHashBalance) Add(addr string, weight int) error {
	if weight <= 0 {
		return errors.New("权重必须大于零")
	}
	c.mux.Lock()
	defer c.mux.Unlock()

	// 根据权重计算虚拟节点的 hash 值
	for i := 0; i < weight; i++ {
		hash := c.hash([]byte(strconv.Itoa(i) + "I" + addr))
		c.keys = append(c.keys, hash)
		c.hashMap[hash] = addr
	}
	sort.Sort(c.keys) // 排序
	return nil
}

// 获取代理服务器
func (c *ConsistentHashBalance) Get(key string) (string, error) {
	if len(c.keys) == 0 {
		return "", errors.New("没有代理转发服务器")
	}
	hash := c.hash([]byte(key))
	idx := sort.Search(len(c.keys), func(i int) bool { return c.keys[i] >= hash })

	if idx == len(c.keys) {
		idx = 0
	}
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.hashMap[c.keys[idx]], nil
}
