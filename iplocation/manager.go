package iplocation

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ipipdotnet/ipdb-go"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/geoip2-golang"
)

// Manager IP 地理位置查询管理器
type Manager struct {
	mu sync.RWMutex

	// IPv4 后端
	v4Source     DBSource
	v4Format     DBFormat
	v4Searcher   *xdb.Searcher  // ip2region IPv4 (buffer 模式并发安全)
	v4GeoReader  *geoip2.Reader // GeoLite2 (备选)
	v4LoadTime   time.Time
	v4FileSize   int64
	v4CreateTime time.Time // 文件创建时间

	// IPv6 后端
	v6Source     DBSource
	v6Format     DBFormat
	v6Searcher   *xdb.Searcher  // ip2region IPv6
	v6GeoReader  *geoip2.Reader // GeoLite2-Country (默认)
	v6LoadTime   time.Time
	v6FileSize   int64
	v6CreateTime time.Time // 文件创建时间

	// ipdb 后端（IPv4+IPv6 共用同一个文件）
	ipdbReader     *ipdb.City
	ipdbLoadTime   time.Time
	ipdbFileSize   int64
	ipdbCreateTime time.Time
}

// NewManager 创建新的 IP 地理位置查询管理器
func NewManager() *Manager {
	return &Manager{
		v4Source: SourceIp2Region,
		v4Format: FormatLegacy,
		v6Source: SourceGeoLite2,
		v6Format: FormatLegacy,
	}
}

// Lookup 查询 IP 地理位置信息，自动判断 IPv4/IPv6
func (m *Manager) Lookup(ipStr string) *IPLocationResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 判断是 IPv4 还是 IPv6
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return &IPLocationResult{Country: "无效IP"}
	}

	// 判断 IP 类型
	if ip.To4() != nil {
		// IPv4
		return m.lookupV4(ipStr)
	} else {
		// IPv6
		return m.lookupV6(ipStr)
	}
}

// lookupV4 查询 IPv4 地址
func (m *Manager) lookupV4(ipStr string) *IPLocationResult {
	if m.v4Source == SourceIp2Region && m.v4Searcher != nil {
		region, err := m.v4Searcher.SearchByStr(ipStr)
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		if region == "" {
			return &IPLocationResult{Country: "未知"}
		}
		return ParseRegion(region, m.v4Format)
	} else if m.v4Source == SourceGeoLite2 && m.v4GeoReader != nil {
		ip := net.ParseIP(ipStr)
		record, err := m.v4GeoReader.Country(ip)
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		countryName := record.Country.Names["zh-CN"]
		if countryName == "" {
			countryName = record.Country.Names["en"]
		}
		return &IPLocationResult{Country: countryName}
	} else if m.v4Source == SourceIpdb && m.ipdbReader != nil {
		info, err := m.ipdbReader.FindMap(ipStr, "CN")
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		return parseIpdbMap(info)
	}

	return &IPLocationResult{Country: "未配置"}
}

// lookupV6 查询 IPv6 地址
func (m *Manager) lookupV6(ipStr string) *IPLocationResult {
	if m.v6Source == SourceIp2Region && m.v6Searcher != nil {
		region, err := m.v6Searcher.SearchByStr(ipStr)
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		if region == "" {
			return &IPLocationResult{Country: "未知"}
		}
		return ParseRegion(region, m.v6Format)
	} else if m.v6Source == SourceGeoLite2 && m.v6GeoReader != nil {
		ip := net.ParseIP(ipStr)
		record, err := m.v6GeoReader.Country(ip)
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		countryName := record.Country.Names["zh-CN"]
		if countryName == "" {
			countryName = record.Country.Names["en"]
		}
		if countryName == "" {
			countryName = "内网"
		}
		return &IPLocationResult{Country: countryName}
	} else if m.v6Source == SourceIpdb && m.ipdbReader != nil {
		info, err := m.ipdbReader.FindMap(ipStr, "CN")
		if err != nil {
			return &IPLocationResult{Country: "查询失败"}
		}
		return parseIpdbMap(info)
	}

	return &IPLocationResult{Country: "未配置"}
}

// LoadV4Ip2Region 加载 IPv4 ip2region 数据库
func (m *Manager) LoadV4Ip2Region(data []byte, format DBFormat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 关闭旧的 searcher
	if m.v4Searcher != nil {
		m.v4Searcher.Close()
		m.v4Searcher = nil
	}

	// 创建新的 searcher (buffer 模式并发安全)
	searcher, err := xdb.NewWithBuffer(xdb.IPv4, data)
	if err != nil {
		return fmt.Errorf("创建 IPv4 searcher 失败: %w", err)
	}

	m.v4Searcher = searcher
	m.v4Source = SourceIp2Region
	m.v4Format = format
	m.v4LoadTime = time.Now()
	m.v4FileSize = int64(len(data))
	m.v4CreateTime = time.Now() // 记录创建时间

	return nil
}

// LoadV4GeoLite2 加载 IPv4 GeoLite2 数据库
func (m *Manager) LoadV4GeoLite2(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 关闭旧的 reader
	if m.v4GeoReader != nil {
		m.v4GeoReader.Close()
		m.v4GeoReader = nil
	}

	// 创建新的 reader
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return fmt.Errorf("创建 IPv4 GeoLite2 reader 失败: %w", err)
	}

	m.v4GeoReader = reader
	m.v4Source = SourceGeoLite2
	m.v4LoadTime = time.Now()
	m.v4FileSize = int64(len(data))
	m.v4CreateTime = time.Now() // 记录创建时间

	return nil
}

// LoadV6Ip2Region 加载 IPv6 ip2region 数据库
func (m *Manager) LoadV6Ip2Region(data []byte, format DBFormat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 关闭旧的 searcher
	if m.v6Searcher != nil {
		m.v6Searcher.Close()
		m.v6Searcher = nil
	}

	// 创建新的 searcher (buffer 模式并发安全)
	searcher, err := xdb.NewWithBuffer(xdb.IPv6, data)
	if err != nil {
		return fmt.Errorf("创建 IPv6 searcher 失败: %w", err)
	}

	m.v6Searcher = searcher
	m.v6Source = SourceIp2Region
	m.v6Format = format
	m.v6LoadTime = time.Now()
	m.v6FileSize = int64(len(data))
	m.v6CreateTime = time.Now() // 记录创建时间

	return nil
}

// LoadV6GeoLite2 加载 IPv6 GeoLite2 数据库
func (m *Manager) LoadV6GeoLite2(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 关闭旧的 reader
	if m.v6GeoReader != nil {
		m.v6GeoReader.Close()
		m.v6GeoReader = nil
	}

	// 创建新的 reader
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return fmt.Errorf("创建 IPv6 GeoLite2 reader 失败: %w", err)
	}

	m.v6GeoReader = reader
	m.v6Source = SourceGeoLite2
	m.v6LoadTime = time.Now()
	m.v6FileSize = int64(len(data))
	m.v6CreateTime = time.Now() // 记录创建时间

	return nil
}

// LoadIpdb 加载 ipdb 数据库（ipdb 支持 IPv4+IPv6，共用同一文件）
func (m *Manager) LoadIpdb(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	reader, err := ipdb.NewCity(filePath)
	if err != nil {
		return fmt.Errorf("创建 ipdb reader 失败: %w", err)
	}
	m.ipdbReader = reader
	m.ipdbLoadTime = time.Now()
	if fi, err2 := os.Stat(filePath); err2 == nil {
		m.ipdbFileSize = fi.Size()
		m.ipdbCreateTime = fi.ModTime()
	}
	return nil
}

// IsIpdbLoaded 返回 ipdb reader 是否已加载
func (m *Manager) IsIpdbLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ipdbReader != nil
}

// ReloadV4 热加载 IPv4 数据库
func (m *Manager) ReloadV4(data []byte, source DBSource, format DBFormat) error {
	if source == SourceIp2Region {
		return m.LoadV4Ip2Region(data, format)
	} else if source == SourceGeoLite2 {
		return m.LoadV4GeoLite2(data)
	}
	return fmt.Errorf("未知的数据源: %s", source)
}

// ReloadV6 热加载 IPv6 数据库
func (m *Manager) ReloadV6(data []byte, source DBSource, format DBFormat) error {
	if source == SourceIp2Region {
		return m.LoadV6Ip2Region(data, format)
	} else if source == SourceGeoLite2 {
		return m.LoadV6GeoLite2(data)
	}
	return fmt.Errorf("未知的数据源: %s", source)
}

// GetStatus 获取当前数据库状态
func (m *Manager) GetStatus() *DBStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := &DBStatus{
		IPv4Source:   string(m.v4Source),
		IPv4Format:   string(m.v4Format),
		IPv4FileSize: m.v4FileSize,
		IPv6Source:   string(m.v6Source),
		IPv6Format:   string(m.v6Format),
		IPv6FileSize: m.v6FileSize,
	}

	// ipdb 来源使用 ipdb 的文件元数据覆盖对应槽位
	if m.v4Source == SourceIpdb {
		status.IPv4FileSize = m.ipdbFileSize
		if !m.ipdbLoadTime.IsZero() {
			status.IPv4LoadTime = m.ipdbLoadTime.Format("2006-01-02 15:04:05")
		}
		if !m.ipdbCreateTime.IsZero() {
			status.IPv4CreateTime = m.ipdbCreateTime.Format("2006-01-02 15:04:05")
		}
	} else {
		if !m.v4LoadTime.IsZero() {
			status.IPv4LoadTime = m.v4LoadTime.Format("2006-01-02 15:04:05")
		}
		if !m.v4CreateTime.IsZero() {
			status.IPv4CreateTime = m.v4CreateTime.Format("2006-01-02 15:04:05")
		}
	}

	if m.v6Source == SourceIpdb {
		status.IPv6FileSize = m.ipdbFileSize
		if !m.ipdbLoadTime.IsZero() {
			status.IPv6LoadTime = m.ipdbLoadTime.Format("2006-01-02 15:04:05")
		}
		if !m.ipdbCreateTime.IsZero() {
			status.IPv6CreateTime = m.ipdbCreateTime.Format("2006-01-02 15:04:05")
		}
	} else {
		if !m.v6LoadTime.IsZero() {
			status.IPv6LoadTime = m.v6LoadTime.Format("2006-01-02 15:04:05")
		}
		if !m.v6CreateTime.IsZero() {
			status.IPv6CreateTime = m.v6CreateTime.Format("2006-01-02 15:04:05")
		}
	}

	return status
}

// Close 关闭所有数据库连接
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.v4Searcher != nil {
		m.v4Searcher.Close()
		m.v4Searcher = nil
	}
	if m.v4GeoReader != nil {
		m.v4GeoReader.Close()
		m.v4GeoReader = nil
	}
	if m.v6Searcher != nil {
		m.v6Searcher.Close()
		m.v6Searcher = nil
	}
	if m.v6GeoReader != nil {
		m.v6GeoReader.Close()
		m.v6GeoReader = nil
	}
	// ipdb.City 无 Close 方法，置 nil 由 GC 回收
	m.ipdbReader = nil
}

// parseIpdbMap 将 ipdb FindMap 返回的字段映射转换为统一结果结构
func parseIpdbMap(info map[string]string) *IPLocationResult {
	get := func(k string) string { return info[k] }
	return &IPLocationResult{
		Country:  get("country_name"),
		Province: get("region_name"),
		City:     get("city_name"),
		ISP:      get("isp_domain"),
		Region:   get("continent_code"),
	}
}

// SetV4Source 设置 IPv4 数据源
func (m *Manager) SetV4Source(source DBSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v4Source = source
}

// SetV6Source 设置 IPv6 数据源
func (m *Manager) SetV6Source(source DBSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v6Source = source
}

// SetBothSourceIpdb 将 IPv4 和 IPv6 数据源同时设置为 ipdb
func (m *Manager) SetBothSourceIpdb() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v4Source = SourceIpdb
	m.v6Source = SourceIpdb
}

// SetV4Format 设置 IPv4 数据格式
func (m *Manager) SetV4Format(format DBFormat) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v4Format = format
}

// SetV6Format 设置 IPv6 数据格式
func (m *Manager) SetV6Format(format DBFormat) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v6Format = format
}
