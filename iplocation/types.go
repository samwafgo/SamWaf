package iplocation

// IPLocationResult 统一的 IP 地理位置查询结果
type IPLocationResult struct {
	Country  string // 国家
	Province string // 省份
	City     string // 城市
	ISP      string // 运营商
	Region   string // 区域/大洲
	District string // 区县
}

// ToSlice 返回兼容老格式的 []string: [国家, 区域, 省份, 城市, ISP]
func (r *IPLocationResult) ToSlice() []string {
	return []string{r.Country, r.Region, r.Province, r.City, r.ISP}
}

// DBFormat IP 数据库字段格式
type DBFormat string

const (
	FormatLegacy     DBFormat = "legacy"     // 国家|区域|省份|城市|ISP (老版本内置)
	FormatOpenSource DBFormat = "opensource" // 国家|省份|城市|网络运营商
	FormatFull       DBFormat = "full"       // 大洲|国家|省份|城市|区县|网络运营商|其他
	FormatStandard   DBFormat = "standard"   // 国家|省份|城市|区县|网络运营商|其他
	FormatCompact    DBFormat = "compact"    // 国家|省份|城市|网络运营商|其他
)

// DBSource IP 数据库来源
type DBSource string

const (
	SourceIp2Region DBSource = "ip2region"
	SourceGeoLite2  DBSource = "geolite2"
	SourceIpdb      DBSource = "ipdb"
)

// DBStatus 数据库状态信息
type DBStatus struct {
	IPv4Source     string `json:"ipv4_source"`
	IPv4Format     string `json:"ipv4_format"`
	IPv4FileSize   int64  `json:"ipv4_file_size"`
	IPv4LoadTime   string `json:"ipv4_load_time"`
	IPv4CreateTime string `json:"ipv4_create_time"`

	IPv6Source     string `json:"ipv6_source"`
	IPv6Format     string `json:"ipv6_format"`
	IPv6FileSize   int64  `json:"ipv6_file_size"`
	IPv6LoadTime   string `json:"ipv6_load_time"`
	IPv6CreateTime string `json:"ipv6_create_time"`
}
