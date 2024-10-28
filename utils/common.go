package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"fmt"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func GetExternalIp() string {
	resp, err := http.Get("http://myexternalip.com/raw")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	//io.Copy(os.Stdout, resp.Body)
	body, _ := ioutil.ReadAll(resp.Body)
	clientIP := fmt.Sprintf("%s", string(body))
	return clientIP
}

func GetCurrentDir() string {
	// 检测环境变量是否存在
	envVar := "SamWafIDE"
	if value, exists := os.LookupEnv(envVar); exists {
		zlog.Info("当前在IDE,环境变量", value)
		return "."
	}

	exePath, err := os.Executable()
	if err != nil {
		zlog.Error("Failed to get executable path:", err)
		return ""
	}
	zlog.Info("当前程序所在文件位置", exePath)
	exeDir := filepath.Dir(exePath)
	return exeDir
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
	// 2、用全局的 cBuff 创建完全基于内存的查询对象。
	searcher, err := xdb.NewWithBuffer(global.GCACHE_IP_CBUFF)
	if err != nil {
		fmt.Printf("failed to create searcher with content: %s\n", err)

	}

	defer searcher.Close()

	// do the search
	var tStart = time.Now()

	// 备注：并发使用，每个 goroutine 需要创建一个独立的 searcher 对象。
	region, err := searcher.SearchByStr(ip)
	if err != nil {
		fmt.Printf("failed to SearchIP(%s): %s\n", ip, err)
		return []string{"无", "无"}
	}

	zlog.Debug("{region: %s, took: %s}\n", region, time.Since(tStart))
	regions := strings.Split(region, "|")

	return regions
}

// PortCheck 检查端口是否可用，可用-true 不可用-false
func PortCheck(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%d", port), time.Second)
	if err != nil {
		return true // Port is available
	}
	defer conn.Close()
	return false // Port is not available
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

// 获取纯域名

func GetPureDomain(host string) string {
	// 检查是否包含端口号
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	return host
}
