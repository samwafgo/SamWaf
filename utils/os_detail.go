package utils

import (
	"SamWaf/common/zlog"
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v4/host"
)

// OSDetail 运行环境详情：用于版本弹窗/运行参数展示，方便用户反馈问题时定位环境
type OSDetail struct {
	GOOS      string `json:"goos"`       //编译目标系统 windows/linux/darwin
	GOARCH    string `json:"goarch"`     //编译目标架构 amd64/arm64
	GoVersion string `json:"go_version"` //编译器版本

	OSName          string `json:"os_name"`          //友好的操作系统名称 如 Ubuntu 24.04.1 LTS / Microsoft Windows Server 2012 R2 Standard
	Platform        string `json:"platform"`         //平台 如 ubuntu / centos / Microsoft Windows 10 Pro
	PlatformFamily  string `json:"platform_family"`  //平台家族 如 debian / rhel
	PlatformVersion string `json:"platform_version"` //平台版本 如 24.04
	KernelVersion   string `json:"kernel_version"`   //内核版本
	KernelArch      string `json:"kernel_arch"`      //内核架构(真实机器架构，32位程序跑在64位系统时与 GOARCH 不同)

	IsWindows    bool `json:"is_windows"`     //是否 Windows 系统
	IsWin7Kernel bool `json:"is_win7_kernel"` //当前系统是否是 Win7/Win8/Server2008R2 内核(6.1/6.2)

	Container      string `json:"container"`      //容器类型：空=非容器；docker/podman/containerd/lxc/oci
	InKubernetes   bool   `json:"in_kubernetes"`  //是否运行在 Kubernetes 中
	IsWSL          bool   `json:"is_wsl"`         //是否运行在 WSL 中
	Virtualization string `json:"virtualization"` //虚拟化类型(仅 guest 角色时给出) 如 kvm/vmware/hyperv
}

var (
	osDetailOnce  sync.Once
	osDetailCache OSDetail

	errHostInfoPanic = errors.New("读取主机信息发生异常")
)

// GetOSDetail 获取运行环境详情(静态信息，进程内只探测一次)
// 探测过程全部容错：任何一项取不到就留空，不会返回错误、也不会 panic
func GetOSDetail() OSDetail {
	osDetailOnce.Do(func() {
		// 基础信息不依赖任何系统调用，先兜底填上，保证即使后续探测异常也有值可展示
		osDetailCache = OSDetail{
			GOOS:      runtime.GOOS,
			GOARCH:    runtime.GOARCH,
			GoVersion: runtime.Version(),
			IsWindows: runtime.GOOS == "windows",
			OSName:    runtime.GOOS,
		}
		defer func() {
			// gopsutil 在部分定制/裁剪系统上可能 panic，这里兜住，保留已填充的基础信息
			if err := recover(); err != nil {
				zlog.Warn("获取系统运行环境信息异常", err)
			}
		}()
		osDetailCache = buildOSDetail()
	})
	return osDetailCache
}

func buildOSDetail() OSDetail {
	detail := OSDetail{
		GOOS:         runtime.GOOS,
		GOARCH:       runtime.GOARCH,
		GoVersion:    runtime.Version(),
		IsWindows:    runtime.GOOS == "windows",
		IsWin7Kernel: safeBool(IsSupportedWindows7Version),
	}

	if info, err := safeHostInfo(); err == nil && info != nil {
		detail.Platform = info.Platform
		detail.PlatformFamily = info.PlatformFamily
		detail.PlatformVersion = info.PlatformVersion
		detail.KernelVersion = info.KernelVersion
		detail.KernelArch = info.KernelArch
		// 只有作为 guest 运行时虚拟化类型才有意义，宿主机(host 角色)不展示
		if strings.EqualFold(info.VirtualizationRole, "guest") {
			detail.Virtualization = info.VirtualizationSystem
		}
	}

	detail.OSName = buildOSName(detail)
	detail.Container = detectContainerRuntime()
	detail.InKubernetes = os.Getenv("KUBERNETES_SERVICE_HOST") != ""
	detail.IsWSL = detectWSL()

	return detail
}

// GetSystemUptimeSeconds 获取系统已运行时长(秒)，取不到返回 0，不会 panic
func GetSystemUptimeSeconds() (seconds uint64) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Warn("读取系统运行时长异常", r)
			seconds = 0
		}
	}()
	up, err := host.Uptime()
	if err != nil {
		zlog.Warn("读取系统运行时长失败:" + err.Error())
		return 0
	}
	return up
}

// FormatDurationCN 把秒数格式化为 "x 天 x 时 x 分 x 秒"
func FormatDurationCN(totalSeconds int64) string {
	if totalSeconds < 0 {
		totalSeconds = 0
	}
	seconds := totalSeconds % 60
	minutes := (totalSeconds / 60) % 60
	hours := (totalSeconds / 3600) % 24
	days := totalSeconds / 86400
	return fmt.Sprintf("%v 天 %v 时 %v 分 %v 秒", days, hours, minutes, seconds)
}

// safeHostInfo 调用 gopsutil 获取主机信息，任何 panic 都转成错误返回
func safeHostInfo() (info *host.InfoStat, err error) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Warn("读取主机信息异常", r)
			info = nil
			err = errHostInfoPanic
		}
	}()
	return host.Info()
}

// safeBool 执行可能触发系统调用的判断函数，异常时返回 false
func safeBool(fn func() bool) (result bool) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Warn("系统信息判断异常", r)
			result = false
		}
	}()
	return fn()
}

// buildOSName 拼一个尽量可读的操作系统名称
func buildOSName(detail OSDetail) string {
	// Linux 优先取 /etc/os-release 的 PRETTY_NAME，如 "Ubuntu 24.04.1 LTS"、"Alpine Linux v3.20"
	if runtime.GOOS == "linux" {
		if pretty := readOSReleasePrettyName(); pretty != "" {
			return pretty
		}
	}
	name := strings.TrimSpace(detail.Platform)
	version := strings.TrimSpace(detail.PlatformVersion)
	if name == "" {
		name = runtime.GOOS
	}
	if version != "" && !strings.Contains(name, version) {
		name = name + " " + version
	}
	return name
}

// readOSReleasePrettyName 读取 /etc/os-release(或 /usr/lib/os-release) 中的 PRETTY_NAME
func readOSReleasePrettyName() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		pretty := ""
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "PRETTY_NAME=") {
				continue
			}
			pretty = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"'`)
			break
		}
		f.Close()
		if pretty != "" {
			return pretty
		}
	}
	return ""
}

// detectContainerRuntime 粗略判断当前进程运行在什么容器里，非容器返回空字符串
func detectContainerRuntime() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	// docker 官方镜像会写入该标记文件
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	// podman/buildah 的标记文件
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "podman"
	}
	// systemd-nspawn / podman / lxc 会注入 container 环境变量
	if env := strings.ToLower(strings.TrimSpace(os.Getenv("container"))); env != "" {
		return env
	}
	// 退回到 cgroup 特征判断(cgroup v1 常见；v2 下 /proc/1/cgroup 可能只有 "0::/")
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := strings.ToLower(string(data))
		switch {
		case strings.Contains(content, "docker"):
			return "docker"
		case strings.Contains(content, "kubepods"):
			return "containerd"
		case strings.Contains(content, "containerd"):
			return "containerd"
		case strings.Contains(content, "lxc"):
			return "lxc"
		}
	}
	// cgroup v2 场景：挂载信息里通常能看到 overlay 根文件系统与容器运行时目录
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		content := strings.ToLower(string(data))
		switch {
		case strings.Contains(content, "/docker/containers/"):
			return "docker"
		case strings.Contains(content, "/containers/storage/"):
			return "podman"
		case strings.Contains(content, "/kubelet/pods/"):
			return "containerd"
		}
	}
	return ""
}

// detectWSL 判断是否运行在 WSL(Windows Subsystem for Linux)
func detectWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	return strings.Contains(content, "microsoft") || strings.Contains(content, "wsl")
}
