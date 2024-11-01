package api

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type WafLogAPi struct {
}

func (w *WafLogAPi) GetDetailApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLog, _ := wafLogService.GetDetailApi(req)
		response.OkWithDetailed(wafLog, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLogAPi) GetListApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, err2 := wafLogService.GetListApi(req)
		if err2 != nil {
			response.FailWithMessage("访问列表失败:"+err2.Error(), c)
		} else {
			response.OkWithDetailed(response.PageResult{
				List:      wafLogs,
				Total:     total,
				PageIndex: req.PageIndex,
				PageSize:  req.PageSize,
			}, "获取成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLogAPi) ExportDBApi(c *gin.Context) {
	if global.GWAF_CAN_EXPORT_DOWNLOAD_LOG == false {
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "导出失败"},
			OperaCnt:        "当前不允许导出",
		})
		response.FailWithMessage("当前不允许导出", c)
		return
	}
	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		response.FailWithMessage("正在切换数据库请等待", c)
		return
	}
	//TODO 必须再验证一次权限
	//是否生成了 还没下载
	if len(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH) > 0 {
		response.FailWithMessage("文件还未下载请等待", c)
		return
	}

	go func() {
		currentDir := utils.GetCurrentDir()
		downLoadDir := currentDir + "/download"
		// 判断备份目录是否存在，不存在则创建
		if _, err := os.Stat(downLoadDir); os.IsNotExist(err) {
			if err := os.MkdirAll(downLoadDir, os.ModePerm); err != nil {
				zlog.Error("创建下载目录失败:", err)
				return
			}
		}
		//处理老旧数据
		duration := 30 * time.Minute
		utils.DeleteOldFiles(downLoadDir, duration)

		// 创建下载文件
		downloadFileName := fmt.Sprintf("local_log_backup_%s.db", time.Now().Format("20060102150405"))
		downloadFilePath := filepath.Join(downLoadDir, downloadFileName)
		err := wafdb.BackupDatabase(global.GWAF_LOCAL_LOG_DB, downloadFilePath)
		if err != nil {
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "DOWNLOAD_LOG", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "导出失败",
				Success:         "true",
			})
		} else {
			global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH = downloadFilePath
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.ExportResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "DOWNLOAD_LOG", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "导出完毕",
				Success:         "true",
			})
		}
	}()
}
func (w *WafLogAPi) DownloadApi(c *gin.Context) {
	if global.GWAF_CAN_EXPORT_DOWNLOAD_LOG == false {
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "下载失败"},
			OperaCnt:        "当前不允许下载",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"message": "当前不允许下载"})
		return
	}
	if len(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to download file,not find file"})
		return
	}
	// 提供文件下载
	c.FileAttachment(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH, "log.db")

	global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH = ""
	// 下载完成后删除文件
	err := os.Remove(global.GWAF_RUNTIME_CURRENT_EXPORT_DB_LOG_FILE_PATH)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete file"})
		return
	}
}
func (w *WafLogAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, _ := wafLogService.GetListByHostCodeApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafLogs,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafLogAPi) GetAllShareDbApi(c *gin.Context) {
	wafShareList, _ := wafShareDbService.GetAllShareDbApi()
	allShareDbRep := make([]response2.AllShareDbRep, len(wafShareList)) // 创建数组
	for i, _ := range wafShareList {

		allShareDbRep[i] = response2.AllShareDbRep{
			StartTime: wafShareList[i].StartTime,
			EndTime:   wafShareList[i].EndTime,
			FileName:  wafShareList[i].FileName,
			Cnt:       wafShareList[i].Cnt,
		}

	}
	response.OkWithDetailed(allShareDbRep, "获取成功", c)
}
