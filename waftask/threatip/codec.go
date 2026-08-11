package threatip

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"
)

// EncodeSnapshot 把 IP/CIDR 列表编码为紧凑快照：先排序去重(便于稳定 sha256)，
// \n 连接后 gzip 压缩。十万条压缩后约数百 KB。返回压缩字节与原始文本 sha256。
func EncodeSnapshot(ips []string) (payload []byte, sha string, count int, err error) {
	uniq := sortedUnique(ips)
	text := strings.Join(uniq, "\n")
	sha = shaOfText(text)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err = zw.Write([]byte(text)); err != nil {
		return nil, "", 0, err
	}
	if err = zw.Close(); err != nil {
		return nil, "", 0, err
	}
	return buf.Bytes(), sha, len(uniq), nil
}

// DecodeSnapshot 解压快照 payload 为 IP/CIDR 列表。空 payload 返回空列表。
func DecodeSnapshot(payload []byte) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

// ShaOf 计算一份 IP/CIDR 列表的内容 sha256，算法与 EncodeSnapshot 完全一致
// （排序去重 → \n 连接 → sha256），因此两者产出的 sha 可以直接互相比较。
//
// 误报排除功能靠这一点成立：「有效集 sha」(内容集剔除排除项后)与快照的「内容 sha」
// 同算法，排除名单为空时二者恒等，存量 landed_sha 升级后仍然有效、不会触发全量重建。
func ShaOf(ips []string) string {
	return shaOfText(strings.Join(sortedUnique(ips), "\n"))
}

func shaOfText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// sortedUnique 排序去重
func sortedUnique(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
