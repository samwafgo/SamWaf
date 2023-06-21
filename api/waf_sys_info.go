package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/utils/zlog"
	"encoding/json"
	"io/ioutil"
	"net/http"

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
	resp, err := http.Get(global.GUPDATE_VERSION_URL)
	if err != nil {
		zlog.Error("读取版本信息失败", err.Error())
		response.FailWithMessage("读取版本信息网络失败", c)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		zlog.Error("读取版本信息失败", err.Error())
		response.FailWithMessage("读取版本信息内容失败", c)
		return
	}
	var updateInfo = model.UpdateVersion{}
	json.Unmarshal(body, &updateInfo)
	if updateInfo.VersionCode > global.GetCurrentVersionInt() {
		response.OkWithDetailed(model.VersionInfo{
			Version:        global.GWAF_RELEASE_VERSION,
			VersionName:    global.GWAF_RELEASE_VERSION_NAME,
			VersionRelease: global.GWAF_RELEASE,
			NeedUpdate:     true,
		}, "有新版本", c)
	} else {
		response.OkWithDetailed(model.VersionInfo{
			Version:        global.GWAF_RELEASE_VERSION,
			VersionName:    global.GWAF_RELEASE_VERSION_NAME,
			VersionRelease: global.GWAF_RELEASE,
			NeedUpdate:     false,
		}, "已经是最新版本", c)
	}

}

// TODO 去升级
func (w *WafSysInfoApi) UpdateApi(c *gin.Context) {

	response.OkWithDetailed(model.VersionInfo{
		Version:        global.GWAF_RELEASE_VERSION,
		VersionName:    global.GWAF_RELEASE_VERSION_NAME,
		VersionRelease: global.GWAF_RELEASE,
	}, "获取成功", c)
}
