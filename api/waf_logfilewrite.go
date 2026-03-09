package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/wafnotify/logfilewriter"
	"github.com/gin-gonic/gin"
	"strconv"
)

type WafLogFileWriteApi struct {
}

// GetPreviewApi 获取日志文件预览（最新N行）
// @Summary      获取日志文件预览
// @Description  获取通知日志文件最新 N 行内容，lines 范围 1-500，默认 100
// @Tags         日志文件写入
// @Accept       json
// @Produce      json
// @Param        lines  query     int  false  "行数（1-500，默认100）"
// @Success      200    {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /logfilewrite/preview [get]
func (w *WafLogFileWriteApi) GetPreviewApi(c *gin.Context) {
	linesStr := c.DefaultQuery("lines", "100")
	lines, err := strconv.Atoi(linesStr)
	if err != nil || lines <= 0 {
		lines = 100
	}
	if lines > 500 {
		lines = 500
	}

	if global.GNOTIFY_LOG_FILE_WRITER == nil {
		response.FailWithMessage("日志文件写入服务未初始化", c)
		return
	}

	// 获取底层 notifier
	writer := getLogFileWriter()
	if writer == nil {
		response.FailWithMessage("日志文件写入服务未初始化", c)
		return
	}

	preview, err := writer.GetLogPreview(lines)
	if err != nil {
		response.FailWithMessage("获取日志预览失败: "+err.Error(), c)
		return
	}

	response.OkWithDetailed(preview, "获取成功", c)
}

// GetCurrentFileInfoApi 获取当前日志文件信息
// @Summary      获取当前日志文件信息
// @Description  获取当前通知日志文件的路径、大小等信息
// @Tags         日志文件写入
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /logfilewrite/currentfile [get]
func (w *WafLogFileWriteApi) GetCurrentFileInfoApi(c *gin.Context) {
	writer := getLogFileWriter()
	if writer == nil {
		response.FailWithMessage("日志文件写入服务未初始化", c)
		return
	}

	fileInfo, err := writer.GetCurrentFileInfo()
	if err != nil {
		response.FailWithMessage("获取文件信息失败: "+err.Error(), c)
		return
	}

	response.OkWithDetailed(fileInfo, "获取成功", c)
}

// GetBackupFilesApi 获取备份文件列表
// @Summary      获取日志备份文件列表
// @Description  获取所有已归档的日志备份文件信息列表
// @Tags         日志文件写入
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /logfilewrite/backupfiles [get]
func (w *WafLogFileWriteApi) GetBackupFilesApi(c *gin.Context) {
	writer := getLogFileWriter()
	if writer == nil {
		response.FailWithMessage("日志文件写入服务未初始化", c)
		return
	}

	files, err := writer.GetBackupFiles()
	if err != nil {
		response.FailWithMessage("获取备份文件列表失败: "+err.Error(), c)
		return
	}

	response.OkWithDetailed(files, "获取成功", c)
}

// ClearLogFileApi 清空当前日志文件
// @Summary      清空当前日志文件
// @Description  清空当前通知日志文件的所有内容
// @Tags         日志文件写入
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "清空成功"
// @Security     ApiKeyAuth
// @Router       /logfilewrite/clear [post]
func (w *WafLogFileWriteApi) ClearLogFileApi(c *gin.Context) {
	writer := getLogFileWriter()
	if writer == nil {
		response.FailWithMessage("日志文件写入服务未初始化", c)
		return
	}

	err := writer.ClearLogFile()
	if err != nil {
		response.FailWithMessage("清空日志文件失败: "+err.Error(), c)
		return
	}

	response.OkWithMessage("清空成功", c)
}

// GetTemplateVariablesApi 获取可用的模板变量列表
// @Summary      获取日志模板变量列表
// @Description  获取日志文件写入模板中可用的所有变量名称及说明
// @Tags         日志文件写入
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /logfilewrite/variables [get]
func (w *WafLogFileWriteApi) GetTemplateVariablesApi(c *gin.Context) {
	variables := logfilewriter.GetTemplateVariables()
	response.OkWithDetailed(variables, "获取成功", c)
}

// getLogFileWriter 获取底层的 LogFileWriter
func getLogFileWriter() *logfilewriter.LogFileWriter {
	if global.GNOTIFY_LOG_FILE_WRITER == nil {
		return nil
	}
	notifier := global.GNOTIFY_LOG_FILE_WRITER.GetNotifier()
	if notifier == nil {
		return nil
	}
	if writer, ok := notifier.(*logfilewriter.LogFileWriter); ok {
		return writer
	}
	return nil
}
