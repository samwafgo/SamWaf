package api

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/utils"
	"SamWaf/wafupdate"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type WafSysInfoApi struct {
}

func getAnnouncement() {
	announcement, err := fetchAnnouncementWithTimeout(10 * time.Second)
	if err != nil {
		zlog.Error(err.Error())
	} else {
		global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_ANNOUNCEMENT, announcement, time.Duration(global.GCONFIG_RECORD_ANNOUNCEMENT_EXPIRE_HOURS)*time.Hour)
	}
}

// 获取公告数据，可指定超时时间
func fetchAnnouncementWithTimeout(timeout time.Duration) (string, error) {
	zlog.Debug(fmt.Sprintf("开始获取公告数据，超时时间: %v", timeout))
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(global.GUPDATE_VERSION_URL + "announcement/public.json?v=" + global.GWAF_RELEASE_VERSION + "&u=" + global.GWAF_USER_CODE)
	if err != nil {
		return "", errors.New(fmt.Sprintf("获取失败: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("服务器返回错误状态码: %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New(fmt.Sprintf("读取内容失败: %v", err))
	}

	return string(body), nil
}

// GetAnnouncementApi 获取公告API
func (w *WafSysInfoApi) GetAnnouncementApi(c *gin.Context) {
	isAnnouncementExist := global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_ANNOUNCEMENT)
	if !isAnnouncementExist {
		// 先尝试快速获取（2秒超时）
		announcement, err := fetchAnnouncementWithTimeout(2 * time.Second)
		if err != nil {
			zlog.Error("快速获取失败: " + err.Error())
			// 如果快速获取失败，启动异步协程进行完整获取（10秒超时）
			go getAnnouncement()
			response.OkWithDetailed(gin.H{
				"code": "fail",
				"data": "",
			}, "获取中，请稍后", c)
		} else {
			// 快速获取成功，保存到缓存
			global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_ANNOUNCEMENT, announcement, time.Duration(global.GCONFIG_RECORD_ANNOUNCEMENT_EXPIRE_HOURS)*time.Hour)
			response.OkWithDetailed(gin.H{
				"code": "success",
				"data": announcement,
			}, "获取成功", c)
		}
	} else {
		announcement, err := global.GCACHE_WAFCACHE.GetString(enums.CACHE_ANNOUNCEMENT)
		if err == nil {
			response.OkWithDetailed(gin.H{
				"code": "success",
				"data": announcement,
			}, "获取成功", c)
		} else {
			response.OkWithDetailed(gin.H{
				"code": "fail",
				"data": "",
			}, "获取失败", c)
		}
	}
}

// SysVersionApi 获取系统版本信息
// @Summary      获取系统版本信息
// @Description  返回当前 SamWaf 的版本号、版本名称及发布状态
// @Tags         系统信息
// @Produce      json
// @Success      200  {object}  response.Response{data=model.VersionInfo}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sysinfo/version [get]
func (w *WafSysInfoApi) SysVersionApi(c *gin.Context) {
	response.OkWithDetailed(model.VersionInfo{
		Version:        global.GWAF_RELEASE_VERSION,
		VersionName:    global.GWAF_RELEASE_VERSION_NAME,
		VersionRelease: global.GWAF_RELEASE,
	}, "获取成功", c)
}

// SysRuntimeInfoApi 获取系统运行环境信息
// @Summary      获取系统运行环境信息
// @Description  返回操作系统类型/发行版及版本、内核、容器(docker/k8s)、虚拟化、运行时长与软件版本，便于反馈问题时定位环境
// @Tags         系统信息
// @Produce      json
// @Success      200  {object}  response.Response{data=model.RuntimeSystemInfo}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sysinfo/runtimeinfo [get]
func (w *WafSysInfoApi) SysRuntimeInfoApi(c *gin.Context) {
	//探测过程全部容错：任何一项拿不到就留空，保证接口一定有返回
	detail := utils.GetOSDetail()

	info := model.RuntimeSystemInfo{
		Version:        global.GWAF_RELEASE_VERSION,
		VersionName:    global.GWAF_RELEASE_VERSION_NAME,
		VersionRelease: global.GWAF_RELEASE,

		OS:        detail.GOOS,
		Arch:      detail.GOARCH,
		GoVersion: detail.GoVersion,

		OSName:          detail.OSName,
		Platform:        detail.Platform,
		PlatformVersion: detail.PlatformVersion,
		KernelVersion:   detail.KernelVersion,
		KernelArch:      detail.KernelArch,

		IsWindows:      detail.IsWindows,
		IsWin7Build:    global.GWAF_RUNTIME_WIN7_VERSION == "true",
		IsWin7Kernel:   detail.IsWin7Kernel,
		Container:      detail.Container,
		InKubernetes:   detail.InKubernetes,
		IsWSL:          detail.IsWSL,
		Virtualization: detail.Virtualization,
		RunAsService:   global.GWAF_RUNTIME_SERVER_TYPE,

		SystemUptimeSeconds:  int64(utils.GetSystemUptimeSeconds()),
		ProcessUptimeSeconds: int64(time.Since(global.GWAF_RUNTIME_PROCESS_START_TIME).Seconds()),
	}
	response.OkWithDetailed(info, "获取成功", c)
}

func (w *WafSysInfoApi) CheckVersionApi(c *gin.Context) {
	if global.GWAF_RUNTIME_IS_UPDATETING == true {
		response.FailWithMessage("正在升级中...请在消息等待结果", c)
		return
	}
	var remoteURL string
	if global.GWAF_RUNTIME_WIN7_VERSION == "true" || utils.IsSupportedWindows7Version() {
		remoteURL = fmt.Sprintf("%s%s", global.GUPDATE_VERSION_URL, "win7/")
	} else {
		remoteURL = fmt.Sprintf("%s%s", global.GUPDATE_VERSION_URL, "")
	}
	var updater = &wafupdate.Updater{
		CurrentVersion: global.GWAF_RELEASE_VERSION, // Manually update the const, or set it using `go build -ldflags="-X main.VERSION=<newver>" -o hello-updater src/hello-updater/main.go`
		ApiURL:         remoteURL,                   // The server hosting `$CmdName/$GOOS-$ARCH.json` which contains the checksum for the binary
		BinURL:         remoteURL,                   // The server hosting the zip file containing the binary application which is a fallback for the patch method
		DiffURL:        remoteURL,                   // The server hosting the binary patch diff for incremental updates
		Dir:            "tmp_update/",               // The directory created by the app when run which stores the cktime file
		CmdName:        "samwaf_update",             // The app name which is appended to the ApiURL to look for an update
		//ForceCheck:     true,                     // For this example, always check for an update unless the version is "dev"
	}
	available, newVer, desc, _ := updater.UpdateAvailable()
	if available {
		global.GWAF_RUNTIME_NEW_VERSION = newVer
		global.GWAF_RUNTIME_NEW_VERSION_DESC = desc
		response.OkWithDetailed(model.VersionInfo{
			Version:           global.GWAF_RELEASE_VERSION,
			VersionName:       global.GWAF_RELEASE_VERSION_NAME,
			VersionRelease:    global.GWAF_RELEASE,
			NeedUpdate:        true,
			VersionNew:        newVer,
			VersionDesc:       desc,
			Container:         utils.DetectContainerRuntime(),
			SelfUpdateAllowed: isSelfUpdateAllowed(),
		}, "有新版本", c)
	} else {
		// 检查是否启用beta版本检测
		if global.GCONFIG_CHECK_BETA_VERSION == 1 {
			available, newVer, desc, _ = updater.UpdateAvailableWithChannel("github")
			if available {
				global.GWAF_RUNTIME_NEW_VERSION = newVer
				global.GWAF_RUNTIME_NEW_VERSION_DESC = desc
				response.OkWithDetailed(model.VersionInfo{
					Version:           global.GWAF_RELEASE_VERSION,
					VersionName:       global.GWAF_RELEASE_VERSION_NAME,
					VersionRelease:    global.GWAF_RELEASE,
					NeedUpdate:        true,
					VersionNew:        newVer,
					VersionDesc:       desc,
					Container:         utils.DetectContainerRuntime(),
					SelfUpdateAllowed: isSelfUpdateAllowed(),
				}, "有新版本(测试版)", c)
			} else {
				response.FailWithMessage("没有最新版本", c)
				return
			}
		} else {
			response.FailWithMessage("没有最新版本", c)
			return
		}
	}

}

// SystemParamsApi 返回认证后才能获取的系统参数（可扩展）
// GET /api/v1/sysinfo/systemparams
func (w *WafSysInfoApi) SystemParamsApi(c *gin.Context) {
	// 当前数据库（sqlite|mysql|postgres），服务端数据库额外给出连接目标（不含密码）
	database := gin.H{"driver": global.GWAF_DB_DRIVER}
	switch global.GWAF_DB_DRIVER {
	case "mysql":
		database["host"] = global.GWAF_MYSQL_HOST
		database["port"] = global.GWAF_MYSQL_PORT
	case "postgres":
		database["host"] = global.GWAF_PG_HOST
		database["port"] = global.GWAF_PG_PORT
	}
	// 当前缓存（memory|redis），redis 额外给出连接目标（不含密码）
	cache := gin.H{"type": global.GCACHE_TYPE}
	if global.GCACHE_TYPE == "redis" {
		cache["host"] = global.GCACHE_REDIS_HOST
		cache["port"] = global.GCACHE_REDIS_PORT
	}
	response.OkWithDetailed(gin.H{
		"emergency_path": "/" + global.GWAF_SECURITY_EMERGENCY_PATH,
		"database":       database,
		"cache":          cache,
	}, "获取成功", c)
}

// RollbackListApi 列出所有可回退的备份版本
// GET /api/v1/sysinfo/rollbacklist
func (w *WafSysInfoApi) RollbackListApi(c *gin.Context) {
	list, err := wafupdate.ListBackups()
	if err != nil {
		response.FailWithMessage("获取备份列表失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(list, "获取成功", c)
}

// RollbackApi 触发版本回退并重启
// GET /api/v1/sysinfo/rollback?version=v1.x.x
func (w *WafSysInfoApi) RollbackApi(c *gin.Context) {
	if global.GWAF_RUNTIME_IS_UPDATETING {
		response.FailWithMessage("正在升级/回退中，请稍后", c)
		return
	}
	version := c.Query("version")
	global.GWAF_RUNTIME_IS_UPDATETING = true
	err := wafupdate.RollbackExecutable(version)
	if err != nil {
		global.GWAF_RUNTIME_IS_UPDATETING = false
		response.FailWithMessage("回退失败: "+err.Error(), c)
		return
	}
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UpdateResultMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "系统即将重启", Server: global.GWAF_CUSTOM_SERVER_NAME},
		Msg:             "版本回退成功，等待重启",
		Success:         "true",
	})
	global.GWAF_CHAN_UPDATE <- 1
	response.OkWithMessage("已发起回退，等待通知结果", c)
}

// 去升级
func (w *WafSysInfoApi) UpdateApi(c *gin.Context) {
	// 获取请求中的 channel 参数
	channel := c.Query("channel")
	if global.GWAF_RUNTIME_IS_UPDATETING == true {
		response.FailWithMessage("正在升级中...请在消息等待结果", c)
		return
	}
	var remoteURL string
	if global.GWAF_RUNTIME_WIN7_VERSION == "true" || utils.IsSupportedWindows7Version() {
		remoteURL = fmt.Sprintf("%s%s", global.GUPDATE_VERSION_URL, "win7/")
	} else {
		remoteURL = fmt.Sprintf("%s%s", global.GUPDATE_VERSION_URL, "")
	}
	// 容器环境默认拦截应用内升级：
	// 容器里的程序文件位于镜像可写层，升级只在本次容器生命周期内有效；容器一旦重建
	// (docker compose up -d / 换镜像 / 重装宿主) 就会回退成镜像自带的旧版本，
	// 而数据库已经被新版本迁移且无法回退，于是形成"旧程序 + 新库"的静默不一致状态
	// (issue #938 现场即如此：库里有 v1.3.24 才有的任务行，跑的却是 v1.3.23)。
	if container := utils.DetectContainerRuntime(); container != "" && global.GCONFIG_ALLOW_CONTAINER_SELFUPDATE != 1 {
		zlog.Warn(fmt.Sprintf("检测到容器环境(%v)，已拦截应用内升级", container))
		response.FailWithMessage(fmt.Sprintf("检测到运行在容器(%v)中，已阻止应用内升级。"+
			"容器内升级只对当前容器有效，容器重建后程序会回退到镜像自带的版本，"+
			"而数据库已被新版本迁移且无法回退，会造成程序与数据版本不一致。"+
			"请改用更新镜像的方式升级(拉取新镜像后重建容器，挂载的数据不受影响)。"+
			"如确需强制升级，可在系统配置中把 allow_container_selfupdate 置为 1", container), c)
		return
	}
	global.GWAF_RUNTIME_IS_UPDATETING = true
	var updater = &wafupdate.Updater{
		CurrentVersion: global.GWAF_RELEASE_VERSION, // Manually update the const, or set it using `go build -ldflags="-X main.VERSION=<newver>" -o hello-updater src/hello-updater/main.go`
		ApiURL:         remoteURL,                   // The server hosting `$CmdName/$GOOS-$ARCH.json` which contains the checksum for the binary
		BinURL:         remoteURL,                   // The server hosting the zip file containing the binary application which is a fallback for the patch method
		DiffURL:        remoteURL,                   // The server hosting the binary patch diff for incremental updates
		Dir:            "tmp_update/",               // The directory created by the app when run which stores the cktime file
		CmdName:        "samwaf_update",             // The app name which is appended to the ApiURL to look for an update
		//ForceCheck:     true,                     // For this example, always check for an update unless the version is "dev"
		OnSuccessfulUpdate: func() {
			global.GWAF_RUNTIME_IS_UPDATETING = false
			zlog.Info("OnSuccessfulUpdate 升级成功")
			wafDelayMsgService.Add("升级结果", "升级结果", "升级成功，当前版本为："+global.GWAF_RUNTIME_NEW_VERSION+" 版本说明:"+global.GWAF_RUNTIME_NEW_VERSION_DESC)
			global.GWAF_CHAN_UPDATE <- 1
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UpdateResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "系统即将重启", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "升级成功，等待重启",
				Success:         "true",
			})
		},
	}
	go func() {
		// 备份当前可执行文件
		err := wafupdate.BackupExecutable()
		if err != nil {
			zlog.Error("备份可执行文件失败:", err)
			// 备份失败不影响升级流程，继续执行
		}

		// try to update
		if channel != "" {
			err := updater.BackgroundRunWithChannel(channel)
			if err != nil {

				global.GWAF_RUNTIME_IS_UPDATETING = false
				//发送websocket 推送消息
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UpdateResultMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "升级结果", Server: global.GWAF_CUSTOM_SERVER_NAME},
					Msg:             "升级错误:" + err.Error(),
					Success:         "False",
				})
				zlog.Info("Failed to update app:", err)
			}
		} else {
			err := updater.BackgroundRun()
			if err != nil {

				global.GWAF_RUNTIME_IS_UPDATETING = false
				//发送websocket 推送消息
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UpdateResultMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "升级结果", Server: global.GWAF_CUSTOM_SERVER_NAME},
					Msg:             "升级错误:" + err.Error(),
					Success:         "False",
				})
				zlog.Info("Failed to update app:", err)
			}
		}

	}()
	response.OkWithMessage("已发起升级，等待通知结果", c)
}

// isSelfUpdateAllowed 当前环境是否允许走应用内升级。
// 非容器恒为 true；容器环境默认 false，可由 allow_container_selfupdate 配置放行。
func isSelfUpdateAllowed() bool {
	if utils.DetectContainerRuntime() == "" {
		return true
	}
	return global.GCONFIG_ALLOW_CONTAINER_SELFUPDATE == 1
}
