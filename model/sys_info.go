package model

type VersionInfo struct {
	NeedUpdate     bool   `json:"need_update"`
	Version        string `json:"version"`
	VersionName    string `json:"version_name"`
	VersionRelease string `json:"version_release"`
	VersionNew     string `json:"version_new"`
	VersionDesc    string `json:"version_desc"`
	// 容器类型：空=非容器；docker/podman/containerd/lxc/oci
	// 容器环境下应用内升级只在本次容器生命周期有效，容器重建即回退，故前端应引导用户改用更新镜像的方式
	Container string `json:"container"`
	// 当前环境是否允许走应用内升级（容器环境默认为 false，可由 allow_container_selfupdate 配置放行）
	SelfUpdateAllowed bool `json:"self_update_allowed"`
}

// RuntimeSystemInfo 系统运行环境信息(供前端版本弹窗展示，便于用户反馈问题时定位环境)
// 说明：所有字段都是"取不到就为空/零值"，前端按需隐藏，不会因为某项探测失败而整体失败
type RuntimeSystemInfo struct {
	//软件信息
	Version        string `json:"version"`         //软件版本Code 如 v1.0.0
	VersionName    string `json:"version_name"`    //软件版本 如 20241028
	VersionRelease string `json:"version_release"` //是否正式版 "true"/"false"

	//编译信息
	OS        string `json:"os"`         //编译目标系统 windows/linux/darwin
	Arch      string `json:"arch"`       //编译目标架构 amd64/arm64
	GoVersion string `json:"go_version"` //编译器版本

	//操作系统信息
	OSName          string `json:"os_name"`          //操作系统名称 如 Ubuntu 24.04.1 LTS / Microsoft Windows Server 2012 R2 Standard
	Platform        string `json:"platform"`         //平台 如 ubuntu
	PlatformVersion string `json:"platform_version"` //平台版本 如 24.04
	KernelVersion   string `json:"kernel_version"`   //内核版本
	KernelArch      string `json:"kernel_arch"`      //内核架构(真实机器架构)

	//特殊环境标记(前端按条件展示)
	IsWindows      bool   `json:"is_windows"`     //是否 Windows 系统
	IsWin7Build    bool   `json:"is_win7_build"`  //当前二进制是否 Win7 专版
	IsWin7Kernel   bool   `json:"is_win7_kernel"` //当前系统是否 Win7/Win8/Server2008R2 内核
	Container      string `json:"container"`      //容器类型：空=非容器；docker/podman/containerd/lxc
	InKubernetes   bool   `json:"in_kubernetes"`  //是否运行在 Kubernetes 中
	IsWSL          bool   `json:"is_wsl"`         //是否运行在 WSL 中
	Virtualization string `json:"virtualization"` //虚拟化类型 如 kvm/vmware/hyperv，空=未识别
	RunAsService   bool   `json:"run_as_service"` //是否以系统服务方式启动

	//运行时长
	SystemUptimeSeconds  int64 `json:"system_uptime_seconds"`  //操作系统已运行时长(秒)，0=未取到
	ProcessUptimeSeconds int64 `json:"process_uptime_seconds"` //SamWaf 进程已运行时长(秒)
}
