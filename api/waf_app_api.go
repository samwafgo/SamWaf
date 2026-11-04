package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"SamWaf/wafapppath"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const appUploadMaxBytes = 200 * 1024 * 1024 // 200 MB

type WafAppApi struct {
	lifecycle appLifecycle
}

func (w *WafAppApi) GetFeatureStatusApi(c *gin.Context) {
	response.OkWithData(gin.H{"enabled": global.GWAF_CAN_APP_MANAGE}, c)
}

// VerifyPasswordApi 验证应用操作密码是否正确（中间件通过即成功，无其他逻辑）
func (w *WafAppApi) VerifyPasswordApi(c *gin.Context) {
	response.OkWithData("ok", c)
}

// DirectoryPreviewApi 解析应用目录预览（不落盘）：空目录按默认规则派生，显式目录校验允许范围
func (w *WafAppApi) DirectoryPreviewApi(c *gin.Context) {
	var req request.WafAppDirPreviewReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if !wafapppath.IsSafeCode(req.Code) {
		response.FailWithMessage("应用编号格式不正确", c)
		return
	}
	response.OkWithData(wafapppath.Resolve(req.Code, req.AppDir, global.GWAF_APP_ALLOW_DIRS), c)
}

// AddApi 新增应用
func (w *WafAppApi) AddApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppAdd)
	defer audit.write(c)
	var req request.WafAppAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	audit.code, audit.name, audit.stage = req.Code, req.Name, "validate"
	if req.Name == "" || req.StartCmd == "" {
		response.FailWithMessage("应用名称和启动命令不能为空", c)
		return
	}
	if req.Code != "" && !wafapppath.IsSafeCode(req.Code) {
		response.FailWithMessage("应用编号格式不正确", c)
		return
	}
	if wafAppService.CheckIsExist(req.Name) > 0 {
		response.FailWithMessage("应用名称已存在", c)
		return
	}
	audit.stage = "save"
	app, err := wafAppService.AddApi(req)
	if err != nil {
		response.FailWithMessage("添加失败: "+err.Error(), c)
		return
	}

	audit.app(app)
	changes := diffFields([]struct{ key, label, oldV, newV string }{
		{"start_cmd", "启动命令", "", req.StartCmd},
		{"app_dir", "工作目录", "", app.AppDir},
		{"env", "环境变量", "", req.Env},
		{"stop_cmd", "停止命令", "", req.StopCmd},
	})
	wafAppChangeLogService.Record(app.Code, app.Name, "新增",
		c.GetString("loginAccount"), utils.GetManageClientIP(c), changes)
	audit.stage = "submit"

	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_NEW,
		Content: *app,
	}
	audit.ok("submitted")
	response.OkWithMessage("应用已添加，初始化指令已提交，请查看运行状态", c)
}

// GetListApi 获取应用列表
func (w *WafAppApi) GetListApi(c *gin.Context) {
	var req request.WafAppSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}
	if req.PageIndex <= 0 {
		req.PageIndex = 1
	}
	list, total := wafAppService.GetListApi(req)

	type AppWithStatus struct {
		Id              string      `json:"id"`
		Code            string      `json:"code"`
		Name            string      `json:"name"`
		AppDir          string      `json:"app_dir"`
		StartCmd        string      `json:"start_cmd"`
		AutoStart       int         `json:"auto_start"`
		StartStatus     int         `json:"start_status"`
		StopMode        string      `json:"stop_mode"`
		StopTimeout     int         `json:"stop_timeout"`
		RestartPolicy   string      `json:"restart_policy"`
		RestartDelay    int         `json:"restart_delay"`
		MaxRestartCount int         `json:"max_restart_count"`
		LogMaxLines     int         `json:"log_max_lines"`
		Remarks         string      `json:"remarks"`
		RunStatus       int         `json:"run_status"`
		Pid             int         `json:"pid"`
		RestartCount    int         `json:"restart_count"`
		RecentChanges   interface{} `json:"recent_changes"`
		ChangeLogCount  int64       `json:"change_log_count"`
	}

	result := make([]AppWithStatus, 0, len(list))
	for _, app := range list {
		rt := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetRuntimeStatus(app.Code)
		recentChanges := wafAppChangeLogService.GetRecentByCode(app.Code, 5)
		changeLogCount := wafAppChangeLogService.GetCountByCode(app.Code)
		result = append(result, AppWithStatus{
			Id:              app.Id,
			Code:            app.Code,
			Name:            app.Name,
			AppDir:          app.AppDir,
			StartCmd:        app.StartCmd,
			AutoStart:       app.AutoStart,
			StartStatus:     app.StartStatus,
			StopMode:        app.StopMode,
			StopTimeout:     app.StopTimeout,
			RestartPolicy:   app.RestartPolicy,
			RestartDelay:    app.RestartDelay,
			MaxRestartCount: app.MaxRestartCount,
			LogMaxLines:     app.LogMaxLines,
			Remarks:         app.Remarks,
			RunStatus:       rt.Status,
			Pid:             rt.Pid,
			RestartCount:    rt.RestartCount,
			RecentChanges:   recentChanges,
			ChangeLogCount:  changeLogCount,
		})
	}
	response.OkWithDetailed(gin.H{"list": result, "total": total}, "查询成功", c)
}

// GetDetailApi 获取应用详情
func (w *WafAppApi) GetDetailApi(c *gin.Context) {
	var req request.WafAppDetailReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithData(wafAppService.GetDetailApi(req), c)
}

// ModifyApi 修改应用配置
func (w *WafAppApi) ModifyApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppEdit)
	defer audit.write(c)
	var req request.WafAppEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}

	audit.stage = "lookup"
	oldApp := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	if oldApp == nil || oldApp.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}

	audit.app(oldApp)
	audit.stage = "save"
	if err := wafAppService.ModifyApi(req); err != nil {
		response.FailWithMessage("修改失败: "+err.Error(), c)
		return
	}

	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	audit.app(app)
	changesJSON := diffFields([]struct{ key, label, oldV, newV string }{
		{"start_cmd", "启动命令", oldApp.StartCmd, req.StartCmd},
		{"app_dir", "工作目录", oldApp.AppDir, app.AppDir},
		{"env", "环境变量", oldApp.Env, req.Env},
		{"stop_cmd", "停止命令", oldApp.StopCmd, req.StopCmd},
	})
	if changesJSON != "[]" {
		wafAppChangeLogService.Record(oldApp.Code, req.Name, "修改",
			c.GetString("loginAccount"), utils.GetManageClientIP(c), changesJSON)
	}

	audit.stage = "submit"
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_UPDATE,
		Content: *app,
	}
	audit.ok("submitted")
	response.OkWithMessage("配置已保存，更新指令已提交，请查看运行状态", c)
}

// DelApi 删除应用
func (w *WafAppApi) DelApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppDel)
	defer audit.write(c)
	var req request.WafAppDelReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	audit.stage = "lookup"
	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}
	audit.app(app)
	audit.stage = "submit"
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:       enums.ChanComTypeApp,
		OpType:     enums.OP_TYPE_DELETE,
		OldContent: *app,
	}
	audit.ok("submitted")
	response.OkWithMessage("删除指令已提交，请刷新应用列表查看结果", c)
}

// StartApi 启动应用
func (w *WafAppApi) StartApi(c *gin.Context) {
	w.submitAppOperation(c, model.AuditEventAppStart, enums.OP_TYPE_APP_START, "启动指令已提交，请查看运行状态")
}

// StopApi 停止应用
func (w *WafAppApi) StopApi(c *gin.Context) {
	w.submitAppOperation(c, model.AuditEventAppStop, enums.OP_TYPE_APP_STOP, "停止指令已提交，请查看运行状态")
}

// RestartApi 重启应用
func (w *WafAppApi) RestartApi(c *gin.Context) {
	w.submitAppOperation(c, model.AuditEventAppRestart, enums.OP_TYPE_APP_RESTART, "重启指令已提交，请查看运行状态")
}

// GetStatusApi 查询应用运行状态
func (w *WafAppApi) GetStatusApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	rt := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetRuntimeStatus(req.Code)
	lastError, errorTime := rt.LastError, rt.ErrorTime.Format(time.RFC3339)
	if lastError == "" {
		errorTime = ""
	}
	response.OkWithData(gin.H{
		"code":          rt.Code,
		"pid":           rt.Pid,
		"run_status":    rt.Status,
		"start_time":    rt.StartTime,
		"restart_count": rt.RestartCount,
		"last_error":    lastError,
		"error_time":    errorTime,
	}, c)
}

// GetLogsApi 获取应用日志
func (w *WafAppApi) GetLogsApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	logs := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetLogs(req.Code)
	if logs == nil {
		logs = []string{}
	}
	response.OkWithData(gin.H{"logs": logs}, c)
}

// ClearLogsApi 清空应用日志
func (w *WafAppApi) ClearLogsApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppClearLogs)
	defer audit.write(c)
	var req request.WafAppCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	audit.code, audit.stage = req.Code, "validate"
	if !wafapppath.IsSafeCode(req.Code) {
		response.FailWithMessage("应用编号格式不正确", c)
		return
	}
	audit.stage = "lookup"
	app := wafAppService.GetDetailByCodeApi(req.Code)
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}
	audit.app(app)
	audit.stage = "clear_logs"
	globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.ClearLogs(req.Code)
	audit.ok("logs_cleared")
	response.OkWithMessage("日志已清空", c)
}

// UploadFileApi 上传文件到应用目录
func (w *WafAppApi) UploadFileApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppUpload)
	defer audit.write(c)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, appUploadMaxBytes)
	code := c.PostForm("code")
	expectedHash := c.PostForm("hash")
	audit.code, audit.stage = code, "validate"
	if !wafapppath.IsSafeCode(code) {
		response.FailWithMessage("应用编号格式不正确", c)
		return
	}
	audit.stage = "lookup"
	app := wafAppService.GetDetailByCodeApi(code)
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}
	audit.app(app)
	audit.stage = "read_upload"
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		response.FailWithMessage("获取文件失败", c)
		return
	}
	defer file.Close()
	audit.filename = appSafeFilename(header.Filename)
	audit.stage = "upload_file"
	if err := wafAppService.UploadFile(code, audit.filename, file, expectedHash); err != nil {
		response.FailWithMessage("上传失败: "+err.Error(), c)
		return
	}
	recordAppFileChange(c, audit, "上传", "上传文件")
	audit.ok("file_saved")
	response.OkWithMessage("上传成功", c)
}

// UpgradeApi 升级应用（停止→备份→替换→重启）
func (w *WafAppApi) UpgradeApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppUpgrade)
	defer audit.write(c)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, appUploadMaxBytes)
	code := c.PostForm("code")
	expectedHash := c.PostForm("hash")
	audit.code, audit.stage = code, "validate"
	if !wafapppath.IsSafeCode(code) {
		response.FailWithMessage("应用编号格式不正确", c)
		return
	}
	audit.stage = "lookup"
	app := wafAppService.GetDetailByCodeApi(code)
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}
	audit.app(app)
	audit.stage = "read_upload"
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		response.FailWithMessage("获取文件失败", c)
		return
	}
	defer file.Close()
	audit.filename = appSafeFilename(header.Filename)
	audit.stage = "stop"
	if err := w.fileEngine().StopApp(code); err != nil {
		response.FailWithMessage("停止应用失败，未替换文件", c)
		return
	}
	audit.stage = "replace_file"
	if err := wafAppService.UpgradeApp(code, audit.filename, file, expectedHash); err != nil {
		audit.stage = "replace_failed_app_disabled"
		if app.StartStatus != 0 {
			audit.stage = "replace_failed_restart_requested"
			if startErr := w.fileEngine().StartApp(code); startErr != nil {
				audit.stage = "replace_failed_restart_failed"
			}
		}
		response.FailWithMessage("文件替换失败: "+err.Error()+"，请查看运行状态", c)
		return
	}
	recordAppFileChange(c, audit, "升级", "升级文件")
	if app.StartStatus == 0 {
		audit.ok("file_replaced_app_disabled")
		response.OkWithMessage("文件已替换，应用已停用，未启动", c)
		return
	}
	audit.stage = "file_replaced_restart_failed"
	if err := w.fileEngine().StartApp(code); err != nil {
		response.FailWithMessage("文件已替换，启动请求失败，请查看运行状态", c)
		return
	}
	audit.ok("file_replaced_restart_requested")
	response.OkWithMessage("文件已替换，已请求启动，请查看运行状态", c)
}

// RollbackApi 回滚应用到备份版本
func (w *WafAppApi) RollbackApi(c *gin.Context) {
	audit := newAppAudit(model.AuditEventAppRollback)
	defer audit.write(c)
	var req request.WafAppRollbackReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	audit.code, audit.filename, audit.stage = req.Code, appSafeFilename(req.Filename), "validate"
	if !wafapppath.IsSafeCode(req.Code) || audit.filename == "" || audit.filename == "." || audit.filename == ".." {
		response.FailWithMessage("应用编号或备份文件名格式不正确", c)
		return
	}
	audit.stage = "lookup"
	app := wafAppService.GetDetailByCodeApi(req.Code)
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}
	audit.app(app)
	audit.stage = "stop"
	if err := w.fileEngine().StopApp(req.Code); err != nil {
		response.FailWithMessage("停止应用失败，未恢复文件", c)
		return
	}
	audit.stage = "restore_file"
	if err := wafAppService.RollbackApp(req.Code, audit.filename); err != nil {
		audit.stage = "restore_failed_app_disabled"
		if app.StartStatus != 0 {
			audit.stage = "restore_failed_restart_requested"
			if startErr := w.fileEngine().StartApp(req.Code); startErr != nil {
				audit.stage = "restore_failed_restart_failed"
			}
		}
		response.FailWithMessage("文件恢复失败: "+err.Error()+"，请查看运行状态", c)
		return
	}
	recordAppFileChange(c, audit, "回滚", "回滚文件")
	if app.StartStatus == 0 {
		audit.ok("file_restored_app_disabled")
		response.OkWithMessage("文件已恢复，应用已停用，未启动", c)
		return
	}
	audit.stage = "file_restored_restart_failed"
	if err := w.fileEngine().StartApp(req.Code); err != nil {
		response.FailWithMessage("文件已恢复，启动请求失败，请查看运行状态", c)
		return
	}
	audit.ok("file_restored_restart_requested")
	response.OkWithMessage("文件已恢复，已请求启动，请查看运行状态", c)
}

// GetBackupsApi 获取备份文件列表
func (w *WafAppApi) GetBackupsApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	backups, err := wafAppService.ListBackups(req.Code)
	if err != nil {
		response.FailWithMessage("获取备份列表失败: "+err.Error(), c)
		return
	}
	response.OkWithData(gin.H{"list": backups}, c)
}

// GetNetStatsApi 查询应用端口与连接 IP
func (w *WafAppApi) GetNetStatsApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	result, err := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetNetStats(req.Code)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithData(result, c)
}

// GetChangeLogsApi 查询应用变更历史
func (w *WafAppApi) GetChangeLogsApi(c *gin.Context) {
	var req request.WafAppChangeLogSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	list, total := wafAppChangeLogService.GetListByCode(req)
	response.OkWithDetailed(gin.H{"list": list, "total": total}, "查询成功", c)
}
