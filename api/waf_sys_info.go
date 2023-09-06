package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/utils/zlog"
	"SamWaf/wafupdate"
	"github.com/gin-gonic/gin"
)

type WafSysInfoApi struct {
}

func (w *WafSysInfoApi) SysVersionApi(c *gin.Context) {
	response.OkWithDetailed(model.VersionInfo{
		Version:        global.GWAF_RELEASE_VERSION,
		VersionName:    global.GWAF_RELEASE_VERSION_NAME,
		VersionRelease: global.GWAF_RELEASE,
	}, "获取成功", c)
}

func (w *WafSysInfoApi) CheckVersionApi(c *gin.Context) {
	var updater = &wafupdate.Updater{
		CurrentVersion: global.GWAF_RELEASE_VERSION, // Manually update the const, or set it using `go build -ldflags="-X main.VERSION=<newver>" -o hello-updater src/hello-updater/main.go`
		ApiURL:         global.GUPDATE_VERSION_URL,  // The server hosting `$CmdName/$GOOS-$ARCH.json` which contains the checksum for the binary
		BinURL:         global.GUPDATE_VERSION_URL,  // The server hosting the zip file containing the binary application which is a fallback for the patch method
		DiffURL:        global.GUPDATE_VERSION_URL,  // The server hosting the binary patch diff for incremental updates
		Dir:            "tmp_update/",               // The directory created by the app when run which stores the cktime file
		CmdName:        "samwaf_update",             // The app name which is appended to the ApiURL to look for an update
		//ForceCheck:     true,                     // For this example, always check for an update unless the version is "dev"
	}
	available, newVer, desc, err := updater.UpdateAvailable()
	if err != nil {
		response.FailWithMessage("发生错误", c)
		return
	}
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
		response.FailWithMessage("没有最新版本", c)
		return
	}

}

// 去升级
func (w *WafSysInfoApi) UpdateApi(c *gin.Context) {
	var updater = &wafupdate.Updater{
		CurrentVersion: global.GWAF_RELEASE_VERSION, // Manually update the const, or set it using `go build -ldflags="-X main.VERSION=<newver>" -o hello-updater src/hello-updater/main.go`
		ApiURL:         global.GUPDATE_VERSION_URL,  // The server hosting `$CmdName/$GOOS-$ARCH.json` which contains the checksum for the binary
		BinURL:         global.GUPDATE_VERSION_URL,  // The server hosting the zip file containing the binary application which is a fallback for the patch method
		DiffURL:        global.GUPDATE_VERSION_URL,  // The server hosting the binary patch diff for incremental updates
		Dir:            "tmp_update/",               // The directory created by the app when run which stores the cktime file
		CmdName:        "samwaf_update",             // The app name which is appended to the ApiURL to look for an update
		//ForceCheck:     true,                     // For this example, always check for an update unless the version is "dev"
		OnSuccessfulUpdate: func() {
			zlog.Info("OnSuccessfulUpdate 升级成功")
			wafDelayMsgService.Add("升级结果", "升级结果", "当前版本为："+global.GWAF_RUNTIME_NEW_VERSION+" 版本说明:"+global.GWAF_RUNTIME_NEW_VERSION_DESC)
			global.GWAF_CHAN_UPDATE <- 1
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.PushBack(innerbean.UpdateResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "升级结果", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "升级成功",
				Success:         "true",
			})
		},
	}
	go func() {
		// try to update
		err := updater.BackgroundRun()
		if err != nil {

			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.PushBack(innerbean.UpdateResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "升级结果", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "升级错误",
				Success:         "False",
			})
			zlog.Info("Failed to update app:", err)
		}
	}()
	response.OkWithMessage("已发起升级，等待通知结果", c)
}
