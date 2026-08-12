package iplocation

import (
	"os"
	"path/filepath"
	"testing"
)

// 这批用例覆盖 GeoLite2 去内嵌后的加载与降级行为。
// 关键前提：程序只内置 IPv4 的 ip2region.xdb；GeoLite2 与 IPv6 库都必须来自磁盘。

const builtinV4Path = "../cmd/samwaf/exedata/ip2region.xdb"

// loadBuiltinV4 读取内置的 IPv4 库并注册。geolite2 传 nil，与主程序保持一致。
func loadBuiltinV4(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(builtinV4Path)
	if err != nil {
		t.Fatal(err)
	}
	SetBuiltinData(b, nil)
	return b
}

// 模拟全新安装：data 目录为空。
// IPv4 应走内置库并能查；IPv6 无任何数据，必须是"不可判定"而不是随便给个国家名。
func TestFreshInstallUsesBuiltin(t *testing.T) {
	loadBuiltinV4(t)
	emptyDir := t.TempDir()

	m := NewManager()
	if err := m.ReloadFromConfig(emptyDir, "ip2region", "ip2region", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if !st.IPv4Builtin || st.IPv4FileSize == 0 {
		t.Fatalf("IPv4 应加载内置数据, got builtin=%v size=%d", st.IPv4Builtin, st.IPv4FileSize)
	}
	if r := m.Lookup("8.8.8.8"); r.Unresolved || r.Country == "" {
		t.Fatalf("IPv4 内置库查询失败: %+v", r)
	} else {
		t.Logf("8.8.8.8 -> %v", r.ToSlice())
	}

	// IPv6 没有内置数据：必须标记 Unresolved，让规则层放行而不是拿"未配置"去比对
	r6 := m.Lookup("2001:4860:4860::8888")
	if !r6.Unresolved {
		t.Fatalf("IPv6 无库时应标记 Unresolved, got %+v", r6)
	}
	if st.IPv6FileSize != 0 {
		t.Fatalf("IPv6 无库时大小应为 0, got %d", st.IPv6FileSize)
	}

	// 可用性判定：只有 ipv4/ip2region 有内置兜底
	if !HasBuiltinSource("ipv4", "ip2region") {
		t.Fatal("ipv4/ip2region 应有内置兜底")
	}
	if HasBuiltinSource("ipv6", "geolite2") {
		t.Fatal("GeoLite2 已去内嵌，不应再报有内置兜底")
	}
	if HasBuiltinFile("geolite2") {
		t.Fatal("HasBuiltinFile(geolite2) 应为 false")
	}
	if HasBuiltinSource("ipv6", "ip2region") {
		t.Fatal("ipv6/ip2region 无内置数据，不应报可用")
	}
	if HasBuiltinSource("ipv4", "ipdb") {
		t.Fatal("ipdb 无内置数据，不应报可用")
	}
}

// 磁盘上的文件必须覆盖内置，且不再标记为内置
func TestUploadedFileOverridesBuiltin(t *testing.T) {
	ip2region := loadBuiltinV4(t)

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "ip2region.xdb"), ip2region, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if err := m.ReloadFromConfig(dataDir, "ip2region", "ip2region", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}
	if m.GetStatus().IPv4Builtin {
		t.Fatal("磁盘已有 ip2region.xdb，IPv4 不应标记为内置")
	}
}

// 老用户配置还是 geolite2，但 mmdb 已不再内置也不在磁盘上：
// IPv4 必须运行时降级到内置 ip2region，绝不能落到"没有地区数据"。
func TestIPv4GeoLite2FallsBackToIp2Region(t *testing.T) {
	loadBuiltinV4(t)
	dataDir := t.TempDir() // 磁盘上没有 mmdb

	m := NewManager()
	if err := m.ReloadFromConfig(dataDir, "geolite2", "ip2region", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if st.IPv4Source != string(SourceIp2Region) {
		t.Fatalf("IPv4 应降级到 ip2region, got %s", st.IPv4Source)
	}
	if r := m.Lookup("8.8.8.8"); r.Unresolved {
		t.Fatalf("降级后 IPv4 仍应可查: %+v", r)
	}
}

// 老用户配置 geolite2、磁盘无 mmdb，但已有 ip2region_v6.xdb：IPv6 应降级用上它。
// 该文件约 35MB 不入库，本机没有就跳过。
func TestIPv6GeoLite2FallsBackToIp2RegionV6(t *testing.T) {
	loadBuiltinV4(t)

	v6, err := os.ReadFile("../data/ip2region_v6.xdb")
	if err != nil {
		t.Skip("本机没有 data/ip2region_v6.xdb，跳过 IPv6 降级用例")
	}
	dataDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dataDir, "ip2region_v6.xdb"), v6, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if err = m.ReloadFromConfig(dataDir, "ip2region", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if st.IPv6Source != string(SourceIp2Region) {
		t.Fatalf("IPv6 应降级到 ip2region, got %s", st.IPv6Source)
	}
	if r := m.Lookup("2001:4860:4860::8888"); r.Unresolved {
		t.Fatalf("降级后 IPv6 仍应可查: %+v", r)
	}
}

// 用户自己把 GeoLite2-Country.mmdb 放进 data/ 时必须照常加载 —— 去内嵌只是不再分发，不是不再支持。
// 仓库里已不带 mmdb，本机没有就跳过。
func TestUserSuppliedGeoLite2StillWorks(t *testing.T) {
	loadBuiltinV4(t)

	mmdb, err := os.ReadFile("../data/GeoLite2-Country.mmdb")
	if err != nil {
		t.Skip("本机没有 data/GeoLite2-Country.mmdb，跳过用户自备用例")
	}
	dataDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dataDir, "GeoLite2-Country.mmdb"), mmdb, 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if err = m.ReloadFromConfig(dataDir, "ip2region", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if st.IPv6Source != string(SourceGeoLite2) {
		t.Fatalf("用户自备 mmdb 时 IPv6 应用 geolite2, got %s", st.IPv6Source)
	}
	if st.IPv6Builtin {
		t.Fatal("用户自备的文件不应标记为内置")
	}
	if r := m.Lookup("2001:4860:4860::8888"); r.Unresolved {
		t.Fatalf("用户自备 mmdb 应能查 IPv6: %+v", r)
	}
}

// 什么库都没有时不能 panic，也不能返回一个会被规则误判的国家名
func TestNoDataAtAllIsUnresolved(t *testing.T) {
	SetBuiltinData(nil, nil)
	defer loadBuiltinV4(t) // 还原，避免影响同包其它用例

	m := NewManager()
	if err := m.ReloadFromConfig(t.TempDir(), "geolite2", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("无任何数据时不应报错, got %v", err)
	}
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if r := m.Lookup(ip); !r.Unresolved {
			t.Fatalf("%s 无库时应标记 Unresolved, got %+v", ip, r)
		}
	}
}
