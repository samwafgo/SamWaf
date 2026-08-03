package ipset

// cidrTrie 是一棵按二进制位展开的前缀树（Patricia 变体），用于判定某个 IP 是否被
// 已插入的任意一个 CIDR 网段覆盖。v4/v6 各用一棵（位宽不同），插入/查询均为 O(前缀深度)
// 常数级，避免了原先"逐条 net.ParseCIDR + Contains"的 O(N) 线性扫描与重复解析。
//
// 说明：本结构一经 BuildMatchSet 构建完成即视为只读，配合引擎 RCU"发布后不可变"语义，
// 请求热路径无锁读。
type cidrNode struct {
	children [2]*cidrNode
	terminal bool // 该节点对应一个已插入网段的结束位置
}

type cidrTrie struct {
	root *cidrNode
}

func newCIDRTrie() *cidrTrie {
	return &cidrTrie{root: &cidrNode{}}
}

// insert 插入一个网段：ipBytes 为网络地址字节（v4=4字节 v6=16字节），prefixLen 为掩码位数。
// 若下降途中已遇到更短的覆盖网段则直接返回（更短网段已覆盖当前网段）；
// 插入成功后清理更深子节点（它们都被本网段覆盖），保持树精简。
func (t *cidrTrie) insert(ipBytes []byte, prefixLen int) {
	if t == nil || t.root == nil || ipBytes == nil {
		return
	}
	if prefixLen <= 0 {
		// /0 覆盖全部
		t.root.terminal = true
		t.root.children[0] = nil
		t.root.children[1] = nil
		return
	}
	node := t.root
	for i := 0; i < prefixLen && i < len(ipBytes)*8; i++ {
		if node.terminal {
			// 已有更短的覆盖网段，无需继续
			return
		}
		bit := (ipBytes[i/8] >> (7 - uint(i%8))) & 1
		if node.children[bit] == nil {
			node.children[bit] = &cidrNode{}
		}
		node = node.children[bit]
	}
	node.terminal = true
	node.children[0] = nil
	node.children[1] = nil
}

// contains 判定完整地址 ipBytes（bitLen=32 或 128）是否被任意已插入网段覆盖。
// 下降途中任一节点为 terminal 即命中（存在覆盖前缀）。
func (t *cidrTrie) contains(ipBytes []byte, bitLen int) bool {
	if t == nil || t.root == nil || ipBytes == nil {
		return false
	}
	node := t.root
	if node.terminal {
		return true
	}
	for i := 0; i < bitLen && i < len(ipBytes)*8; i++ {
		bit := (ipBytes[i/8] >> (7 - uint(i%8))) & 1
		node = node.children[bit]
		if node == nil {
			return false
		}
		if node.terminal {
			return true
		}
	}
	return false
}
