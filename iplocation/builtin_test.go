package iplocation

import (
	"os"
	"testing"
)

// 模拟全新安装：data 目录为空，仅有内置数据
func TestFreshInstallUsesBuiltin(t *testing.T) {
	ip2region, err := os.ReadFile("../cmd/samwaf/exedata/ip2region.xdb")
	if err != nil {
		t.Fatal(err)
	}
	geolite2, err := os.ReadFile("../cmd/samwaf/exedata/GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	SetBuiltinData(ip2region, geolite2)

	emptyDir := t.TempDir() // 全新安装：data 下什么都没有

	m := NewManager()
	if err := m.ReloadFromConfig(emptyDir, "ip2region", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if !st.IPv4Builtin || !st.IPv6Builtin {
		t.Fatalf("应标记为内置数据, got v4=%v v6=%v", st.IPv4Builtin, st.IPv6Builtin)
	}
	if st.IPv4FileSize == 0 || st.IPv6FileSize == 0 {
		t.Fatalf("内置数据大小应非零, got v4=%d v6=%d", st.IPv4FileSize, st.IPv6FileSize)
	}
	t.Logf("状态: v4=%s builtin=%v size=%d | v6=%s builtin=%v size=%d",
		st.IPv4Source, st.IPv4Builtin, st.IPv4FileSize, st.IPv6Source, st.IPv6Builtin, st.IPv6FileSize)

	// 内置数据必须真的能查
	if r := m.Lookup("8.8.8.8"); r.Country == "" || r.Country == "未配置" || r.Country == "查询失败" {
		t.Fatalf("IPv4 内置库查询失败: %+v", r)
	} else {
		t.Logf("8.8.8.8 -> %+v", r.ToSlice())
	}
	if r := m.Lookup("2001:4860:4860::8888"); r.Country == "" || r.Country == "未配置" || r.Country == "查询失败" {
		t.Fatalf("IPv6 内置库查询失败: %+v", r)
	} else {
		t.Logf("2001:4860:4860::8888 -> %+v", r.ToSlice())
	}

	// 保存配置时的可用性判定：默认来源在全新安装下必须可用
	if !HasBuiltinSource("ipv4", "ip2region") {
		t.Fatal("ipv4/ip2region 应有内置兜底")
	}
	if !HasBuiltinSource("ipv6", "geolite2") {
		t.Fatal("ipv6/geolite2 应有内置兜底")
	}
	// 无内置的来源仍应报缺失
	if HasBuiltinSource("ipv6", "ip2region") {
		t.Fatal("ipv6/ip2region 无内置数据，不应报可用")
	}
	if HasBuiltinSource("ipv4", "ipdb") {
		t.Fatal("ipdb 无内置数据，不应报可用")
	}
}

// 上传文件后必须覆盖内置，且不再标记为内置
func TestUploadedFileOverridesBuiltin(t *testing.T) {
	ip2region, err := os.ReadFile("../cmd/samwaf/exedata/ip2region.xdb")
	if err != nil {
		t.Fatal(err)
	}
	geolite2, err := os.ReadFile("../cmd/samwaf/exedata/GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	SetBuiltinData(ip2region, geolite2)

	dataDir := t.TempDir()
	if err := os.WriteFile(dataDir+"/ip2region.xdb", ip2region, 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if err := m.ReloadFromConfig(dataDir, "ip2region", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if st.IPv4Builtin {
		t.Fatal("磁盘已有 ip2region.xdb，IPv4 不应标记为内置")
	}
	if !st.IPv6Builtin {
		t.Fatal("磁盘无 GeoLite2 文件，IPv6 应回落到内置")
	}
}

// IPv4 选 geolite2 时必须读 mmdb，不能把 ip2region.xdb 的字节喂给 GeoLite2 解析器
func TestIPv4GeoLite2UsesMmdbNotXdb(t *testing.T) {
	ip2region, err := os.ReadFile("../cmd/samwaf/exedata/ip2region.xdb")
	if err != nil {
		t.Fatal(err)
	}
	geolite2, err := os.ReadFile("../cmd/samwaf/exedata/GeoLite2-Country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	SetBuiltinData(ip2region, geolite2)

	// 磁盘只有 ip2region.xdb：IPv4 选 geolite2 时不能误用它，应回落到内置 mmdb
	dataDir := t.TempDir()
	if err := os.WriteFile(dataDir+"/ip2region.xdb", ip2region, 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager()
	if err := m.ReloadFromConfig(dataDir, "geolite2", "geolite2", "legacy", "legacy"); err != nil {
		t.Fatalf("ReloadFromConfig 失败: %v", err)
	}

	st := m.GetStatus()
	if st.IPv4Source != "geolite2" || !st.IPv4Builtin {
		t.Fatalf("IPv4 应加载内置 GeoLite2, got source=%s builtin=%v", st.IPv4Source, st.IPv4Builtin)
	}
	if r := m.Lookup("8.8.8.8"); r.Country == "" || r.Country == "未配置" || r.Country == "查询失败" {
		t.Fatalf("IPv4 GeoLite2 查询失败: %+v", r)
	} else {
		t.Logf("geolite2 8.8.8.8 -> %s", r.Country)
	}
}
