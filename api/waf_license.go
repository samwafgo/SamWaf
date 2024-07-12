package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils/zlog"
	"SamWaf/wafreg"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"strconv"
)

// 授权文件
type WafLicenseApi struct {
}

func (w *WafLicenseApi) GetDetailApi(c *gin.Context) {
	var req request.WafLicenseDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		clientMachineInfo := wafreg.GenClientMachineInfo()

		res := response2.LicenseRep{
			License:   global.GWAF_REG_INFO,
			MachineId: clientMachineInfo.MachineID,
		}
		response.OkWithDetailed(res, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLicenseApi) CheckLicense(c *gin.Context) {
	// 获取上传的文件
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		zlog.Error("get form err: %s", err.Error())
		response.FailWithMessage("授权文件解析失败", c)
		return
	}

	// 读取文件内容
	fileContentBytes, err := ioutil.ReadAll(file)
	if err != nil {
		zlog.Error("get form err: %s", err.Error())
		response.FailWithMessage("授权文件解析失败", c)
		return
	}
	//文件内容
	verifyResult, info, err := wafreg.VerifyServerReg(fileContentBytes)

	if verifyResult {
		expiryDay, isExpiry := wafreg.CheckExpiry(info.ExpiryDate)
		if isExpiry {
			response.FailWithMessage("授权信息已经过期", c)
			return
		} else {
			global.GWAF_REG_TMP_REG = fileContentBytes
			response.OkWithMessage("校验成功 授权信息还剩余:"+strconv.Itoa(expiryDay)+"天", c)
			return
		}
	} else {
		response.FailWithMessage("授权文件解析失败", c)
		return
	}
}
func (w *WafLicenseApi) ConfirmApi(c *gin.Context) {
	var req request.WafLicenseConfirmReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GWAF_REG_TMP_REG == nil || len(global.GWAF_REG_TMP_REG) == 0 {
			response.FailWithMessage("保存失败，尚未上传过授权信息", c)
			return
		}

		// 保存到文件
		err = ioutil.WriteFile("./registration_data.bin", global.GWAF_REG_TMP_REG, 0644)
		if err != nil {
			zlog.Error("写入失败", err)
			response.FailWithMessage("保存失败，授权文件写入失败", c)
			return
		}
		global.GWAF_REG_TMP_REG = nil
		clientMachineInfo := wafreg.GenClientMachineInfo()

		//加载授权信息
		verifyResult, info, _ := wafreg.VerifyServerRegByDefaultFile()
		if verifyResult {
			global.GWAF_REG_INFO = info
			expiryDay, isExpiry := wafreg.CheckExpiry(info.ExpiryDate)
			if isExpiry {
				global.GWAF_REG_INFO.IsExpiry = true
			} else {
				global.GWAF_REG_INFO.IsExpiry = false
				zlog.Info("授权信息还剩余:" + strconv.Itoa(expiryDay) + "天")
			}
		}
		res := response2.LicenseRep{
			License:   global.GWAF_REG_INFO,
			MachineId: clientMachineInfo.MachineID,
			Version:   global.GWAF_REG_VERSION,
		}
		response.OkWithDetailed(res, "保存授权成功", c)
	} else {
		response.FailWithMessage("保存授权失败", c)
	}
}
