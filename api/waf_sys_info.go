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
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"time"
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

func (w *WafSysInfoApi) SysVersionApi(c *gin.Context) {
	response.OkWithDetailed(model.VersionInfo{
		Version:        global.GWAF_RELEASE_VERSION,
		VersionName:    global.GWAF_RELEASE_VERSION_NAME,
		VersionRelease: global.GWAF_RELEASE,
	}, "获取成功", c)
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
			Version:        global.GWAF_RELEASE_VERSION,
			VersionName:    global.GWAF_RELEASE_VERSION_NAME,
			VersionRelease: global.GWAF_RELEASE,
			NeedUpdate:     true,
			VersionNew:     newVer,
			VersionDesc:    desc,
		}, "有新版本", c)
	} else {
		available, newVer, desc, _ = updater.UpdateAvailableWithChannel("github")
		if available {
			global.GWAF_RUNTIME_NEW_VERSION = newVer
			global.GWAF_RUNTIME_NEW_VERSION_DESC = desc
			response.OkWithDetailed(model.VersionInfo{
				Version:        global.GWAF_RELEASE_VERSION,
				VersionName:    global.GWAF_RELEASE_VERSION_NAME,
				VersionRelease: global.GWAF_RELEASE,
				NeedUpdate:     true,
				VersionNew:     newVer,
				VersionDesc:    desc,
			}, "有新版本(测试版)", c)
		} else {
			response.FailWithMessage("没有最新版本", c)
			return
		}
	}

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
