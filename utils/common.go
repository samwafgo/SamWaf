package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func GetExternalIp() string {
	// 创建带超时的HTTP客户端,避免DNS解析问题
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	resp, err := client.Get("http://myexternalip.com/raw")
	if err != nil {
		zlog.Debug("GetExternalIp failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		zlog.Debug("ReadAll failed: %v", err)
		return ""
	}

	clientIP := strings.TrimSpace(string(body))
	return clientIP
}

func GetCurrentDir() string {
	// 检测环境变量是否存在
	envVar := "SamWafIDE"
	if _, exists := os.LookupEnv(envVar); exists {
		return "."
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to get executable path:%v", err))
		return ""
	}
	exeDir := filepath.Dir(exePath)
	return exeDir
}

// CheckDebugEnvInfo 检测是否打印debug信息
func CheckDebugEnvInfo() bool {
	// 检测环境变量是否存在
	envVar := "SamWafIDEDebugLog"
	if _, exists := os.LookupEnv(envVar); exists {
		return true
	}

	return false
}
func GetServerByHosts(hosts model.Hosts) string {
	if hosts.Ssl == 1 {
		return "https"
	} else {
		return "http"
	}
}

/*
*

	计算两个自然天数的间隔数
*/
func DiffNatureDays(t1, t2 int64) int {
	var SecondsOfDay int64 = 86400
	if t1 == t2 {
		return -1
	}
	if t1 > t2 {
		t1, t2 = t2, t1
	}

	diffDays := 0
	secDiff := t2 - t1
	if secDiff > SecondsOfDay {
		tmpDays := int(secDiff / SecondsOfDay)
		t1 += int64(tmpDays) * SecondsOfDay
		diffDays += tmpDays
	}

	st := time.Unix(t1, 0)
	et := time.Unix(t2, 0)
	dateFormatTpl := "20060102"
	if st.Format(dateFormatTpl) != et.Format(dateFormatTpl) {
		diffDays += 1
	}

	return diffDays
}

/**字符串->时间对象*/
func Str2Time(formatTimeStr string) time.Time {
	timeLayout := "20060102"
	loc, _ := time.LoadLocation("Local")
	theTime, _ := time.ParseInLocation(timeLayout, formatTimeStr, loc) //使用模板在对应时区转化为time.time类型

	return theTime
}

/*
*
时间转int天
*/
func TimeToDayInt(t time.Time) int {
	day, _ := strconv.Atoi(t.Format("20060102"))
	return day
}
func GetPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
		// log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	return localAddr[0:idx]
}

func GetCountry(ip string) []string {
	if global.GIPLOCATION_MANAGER != nil {
		result := global.GIPLOCATION_MANAGER.Lookup(ip)
		return result.ToSlice() // [国家, 区域, 省份, 城市, ISP]
	}
	return []string{"未知", "", "", "", ""}
}

// CloseIPDatabase 关闭IP数据库
func CloseIPDatabase() {
	if global.GIPLOCATION_MANAGER != nil {
		global.GIPLOCATION_MANAGER.Close()
	}
}

/*
*
通过ip段（CIDR）来查询是否在很多CIDR段内
*/
func CheckIPInRanges(ip string, ipRanges []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // 如果IP地址解析失败，则返回false
	}

	for _, ipRange := range ipRanges {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return false // 如果CIDR格式解析失败，则返回false
		}

		if ipNet.Contains(parsedIP) {
			return true // 如果IP地址在指定的CIDR范围内，则返回true
		}
	}

	return false // 如果IP地址不在任何一个CIDR范围内，则返回false
}

/*
*
通过ip段（CIDR）来查询是否在这个段内
*/
func CheckIPInCIDR(ip string, ipRange string) bool {

	parts := strings.Split(ipRange, "/")
	if len(parts) != 2 {
		// 如果是普通ip
		if ip == ipRange {
			return true
		} else {
			return false
		}
	} else {
		//如果是网段IP
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false // 如果IP地址解析失败，则返回false
		}
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return false // 如果CIDR格式解析失败，则返回false
		}
		if ipNet.Contains(parsedIP) {
			return true // 如果IP地址在指定的CIDR范围内，则返回true
		}
		return false // 如果IP地址不在任何一个CIDR范围内，则返回false
	}
}

// IsValidIPOrNetwork 检查给定的字符串是否为有效的 IP 地址或 IP 段（CIDR）
func IsValidIPOrNetwork(input string) (bool, string) {
	// 尝试解析为 IP 地址
	if ip := net.ParseIP(input); ip != nil {
		return true, "valid IP address"
	}

	// 尝试解析为 IP 段（CIDR）
	_, _, err := net.ParseCIDR(input)
	if err == nil {
		return true, "valid IP network (CIDR)"
	}

	return false, "not a valid IP or IP network (CIDR)"
}

// 检查 JSON 字符串是否为有效的 UTF-8 编码
func CheckJSONValidity(jsonStr []byte) bool {
	for i := 0; i < len(jsonStr); {
		r, size := rune(jsonStr[i]), 1
		switch {
		case r >= 0xF0:
			r, size = rune(jsonStr[i+3]), 4
		case r >= 0xE0:
			r, size = rune(jsonStr[i+2]), 3
		case r >= 0xC0:
			r, size = rune(jsonStr[i+1]), 2
		default:
		}
		if r > 0xFFFF {
			return false
		}
		i += size
	}
	return true
}

/*
*
删除老旧数据
*/
func DeleteOldFiles(dir string, duration time.Duration) error {
	// 遍历目录下的文件
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 如果是文件并且文件创建时间超过指定的时间
		if !info.IsDir() {
			// 获取文件的修改时间（可以近似认为是创建时间）
			fileModTime := info.ModTime()

			// 判断文件是否超过指定的时间（比如30分钟）
			if time.Since(fileModTime) > duration {
				// 删除文件
				zlog.Info("删除陈旧文件:", path)
				err := os.Remove(path)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// 检测是否属于ipv4
func IsValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// 验证IPv6地址是否有效
func IsValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	// 如果解析出的 IP 类型是 IPv6 且不是 IPv4 映射地址（IPv4-mapped IPv6 addresses）
	return parsedIP != nil && strings.Contains(ip, ":") && parsedIP.To4() == nil
}

// 获取纯域名

func GetPureDomain(host string) string {
	// 检查是否包含端口号
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	return host
}

// UpdateFileIsHasNewInfo 检查文件内容并更新
func UpdateFileIsHasNewInfo(filePath, newContent string) error {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 文件不存在，写入新内容
		if err := ioutil.WriteFile(filePath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %v", filePath, err)
		}
	} else {
		// 文件存在，读取当前内容
		currentContent, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", filePath, err)
		}

		// 比较内容是否一致
		if string(currentContent) != newContent {
			// 内容不一致，更新文件
			if err := ioutil.WriteFile(filePath, []byte(newContent), 0644); err != nil {
				return fmt.Errorf("failed to update file %s: %v", filePath, err)
			}
		}
	}
	return nil
}

// IsValidChallengeFile 检查challenge文件是否合法
func IsValidChallengeFile(challengeFile string) bool {
	// 定义一个正则表达式：允许字母、数字、连字符、下划线，且长度在 1 到 255 之间
	// 这里假设合法的文件名不含有特殊字符和空格
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,255}$`)

	// 判断文件名是否符合正则表达式
	return re.MatchString(challengeFile)
}

// CheckPathAndCreate 检测路径如果不存在则创建
func CheckPathAndCreate(path string) error {
	// 检测目录是否存在
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		// 目录不存在，创建目录
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return errors.New("创建目录失败" + err.Error())
		}
		return nil
	} else if err != nil {
		// 发生其他错误
		return errors.New("检查目录失败" + err.Error())
	} else {
		return nil
	}
}

// CheckSSLCertificateExpiry 检查指定主机的 SSL 证书到期情况
// host: 需要检查的主机地址，格式为 "ssl.samwaf.com:443"
func CheckSSLCertificateExpiry(host string) (time.Time, error) {
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("无法连接到主机 %s: %v", host, err)
	}
	defer conn.Close()

	// 获取 SSL 证书的到期时间
	cert := conn.ConnectionState().PeerCertificates[0]
	expiryDate := cert.NotAfter
	// 返回到期时间
	return expiryDate, nil
}

// GetSourceClientIP 获取原始IP
func GetSourceClientIP(ipAndPort string) string {
	ip, _, err := net.SplitHostPort(ipAndPort)
	if err != nil {
		return ""
	} else {
		return ip
	}

}

// IsIP 判断输入是否为 IP 地址（IPv4 或 IPv6）
func IsIP(input string) bool {
	if input == "" {
		return false
	}

	// 去除首尾空格
	input = strings.TrimSpace(input)

	// 使用 net.ParseIP 解析
	// 如果是有效的 IP，返回非 nil
	return net.ParseIP(input) != nil
}

// GetManageClientIP 获取管理端客户端真实IP。
// 安全默认：未配置代理头（GCONFIG_MANAGE_PROXY_HEADER 为空）时直接返回网络层 IP（c.RemoteIP()）。
// 即便配置了代理头，也仅当“直连对端 c.RemoteIP() 属于可信代理网段 GCONFIG_MANAGE_TRUSTED_PROXIES”
// 时才采信代理头；否则一律用网络层 IP。防止任意直连客户端伪造 X-Forwarded-For/X-Real-IP 绕过
// 登录错误锁定 / 管理端 IP 白名单 / 令牌 IP 绑定。
func GetManageClientIP(c *gin.Context) string {
	remoteIP := c.RemoteIP()
	// 未配置代理头 → 直接用网络层 IP
	if global.GCONFIG_MANAGE_PROXY_HEADER == "" {
		return remoteIP
	}
	// 配了代理头，但只信任来自“可信代理”的头；否则用网络层 IP
	if !isTrustedManageProxy(remoteIP) {
		return remoteIP
	}
	for _, header := range strings.Split(global.GCONFIG_MANAGE_PROXY_HEADER, ",") {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		val := c.GetHeader(header)
		if val == "" {
			continue
		}
		// 从右往左取第一个“非可信代理”的 IP：反向代理按追加语义
		// (nginx $proxy_add_x_forwarded_for) 把真实客户端 IP 追加在右侧、客户端伪造的值留在左侧，
		// 故取最右侧的非可信 hop 才是真实客户端；逐个跳过可信代理链。取最左会取到伪造值。
		parts := strings.Split(val, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if !IsValidIPv4(ip) && !IsValidIPv6(ip) {
				continue
			}
			if isTrustedManageProxy(ip) {
				continue // 跳过可信代理 hop
			}
			return ip
		}
	}
	return remoteIP
}

// isTrustedManageProxy 判断直连对端 IP 是否落在管理端可信代理网段
// GCONFIG_MANAGE_TRUSTED_PROXIES（CIDR 或单 IP，逗号分隔）内。
// 留空 → 返回 false（不信任任何代理头，安全默认）。
func isTrustedManageProxy(remoteIP string) bool {
	if global.GCONFIG_MANAGE_TRUSTED_PROXIES == "" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(remoteIP))
	if ip == nil {
		return false
	}
	for _, entry := range strings.Split(global.GCONFIG_MANAGE_TRUSTED_PROXIES, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil && ipnet.Contains(ip) {
				return true
			}
			continue
		}
		if single := net.ParseIP(entry); single != nil && single.Equal(ip) {
			return true
		}
	}
	return false
}
