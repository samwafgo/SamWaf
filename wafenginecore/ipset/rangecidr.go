package ipset

import "bytes"

// rangecidr.go 把「IP 闭区间」精确分解为一组 CIDR 前缀，使区间也能复用 cidrTrie 的
// O(前缀深度) 查询，热路径不必为区间再多一次线性扫描。
//
// 分解是精确等价的（不是近似）：分解结果的并集恰好等于原区间，一个地址不多、一个不少。
// 条数有可证明上界：IPv4 ≤ 62 条，IPv6 ≤ 254 条（每侧最多 bits-1 条），
// 所以无需截断保护，也不会因为用户写一个大区间而撑爆内存。
//
// 通配符不能这么处理：10.*.1.* 展开是 65536 条，*.*.*.5 是 1600 万条，
// 因此不连续掩码的通配符仍走 MatchSet 的线性表。

type prefixEntry struct {
	Net  []byte // 已对齐的网络地址
	Bits int    // 前缀位数
}

// rangeToPrefixes 把闭区间 [start,end] 分解为最少的 CIDR 前缀集合。
// start/end 必须等长（4 或 16）且 start <= end；不满足时返回 nil。
func rangeToPrefixes(start, end []byte) []prefixEntry {
	if len(start) == 0 || len(start) != len(end) || bytes.Compare(start, end) > 0 {
		return nil
	}
	bits := len(start) * 8
	cur := append([]byte(nil), start...)
	out := make([]prefixEntry, 0, 8)
	for bytes.Compare(cur, end) <= 0 {
		// 从当前位置能起步的最大块：受「地址对齐」和「不能越过 end」双重限制
		n := trailingZeroBits(cur)
		if n > bits {
			n = bits
		}
		for n > 0 && bytes.Compare(orLowBits(cur, n), end) > 0 {
			n--
		}
		out = append(out, prefixEntry{Net: append([]byte(nil), cur...), Bits: bits - n})
		// cur += 2^n；溢出说明已经走到地址空间顶端，区间结束
		if !addPow2(cur, n) {
			break
		}
	}
	return out
}

// trailingZeroBits 统计末尾连续 0 比特数；全 0 时返回总位数。
func trailingZeroBits(b []byte) int {
	n := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			n += 8
			continue
		}
		v := b[i]
		for v&1 == 0 {
			n++
			v >>= 1
		}
		break
	}
	return n
}

// orLowBits 返回 b 的副本，并把最低 n 位全部置 1（即该块的广播地址）。
func orLowBits(b []byte, n int) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0 && n > 0; i-- {
		if n >= 8 {
			out[i] = 0xff
			n -= 8
		} else {
			out[i] |= byte(1<<uint(n)) - 1
			n = 0
		}
	}
	return out
}

// addPow2 就地把 b 加上 2^n，溢出返回 false。
func addPow2(b []byte, n int) bool {
	if n >= len(b)*8 {
		// 加上整个地址空间必然溢出（对应 [0,全F] 这种整段区间，一条 /0 已经覆盖完）
		return false
	}
	carry := byte(1) << uint(n%8)
	for i := len(b) - 1 - n/8; i >= 0; i-- {
		sum := uint16(b[i]) + uint16(carry)
		b[i] = byte(sum)
		if sum <= 0xff {
			return true
		}
		carry = 1
	}
	return false
}
