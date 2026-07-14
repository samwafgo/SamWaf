package iplocation

// 内置数据库字节，由 cmd/samwaf 启动时用 //go:embed 资源注入。
// 全新安装（data 目录下无任何 ip 库文件）时，manager 直接以这些字节加载，
// 因此判断某个数据源是否可用不能只看磁盘文件，必须叠加内置兜底。
var (
	builtinIp2RegionV4 []byte
	builtinGeoLite2    []byte
)

// SetBuiltinData 注册内置数据库字节，须在任何加载动作之前调用一次。
func SetBuiltinData(ip2RegionV4, geoLite2 []byte) {
	builtinIp2RegionV4 = ip2RegionV4
	builtinGeoLite2 = geoLite2
}

// HasBuiltinFile 指定数据文件是否有内置兜底。
// key 与状态接口 file_exists 的键一致：ip2region_v4 / ip2region_v6 / geolite2 / ipdb。
// 目前仅内置了 IPv4 的 ip2region.xdb 和 GeoLite2-Country.mmdb。
func HasBuiltinFile(key string) bool {
	switch key {
	case "ip2region_v4":
		return len(builtinIp2RegionV4) > 0
	case "geolite2":
		return len(builtinGeoLite2) > 0
	}
	return false
}

// HasBuiltinSource 指定 ipType(ipv4/ipv6) + source 组合是否有内置数据可用。
func HasBuiltinSource(ipType, source string) bool {
	switch DBSource(source) {
	case SourceIp2Region:
		return ipType == "ipv4" && len(builtinIp2RegionV4) > 0
	case SourceGeoLite2:
		return len(builtinGeoLite2) > 0
	}
	return false
}
