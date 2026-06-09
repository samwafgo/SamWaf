package api

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const appUploadMaxBytes = 200 * 1024 * 1024 // 200 MB

type WafAppApi struct{}

// recordSysLog 写安全审计日志到日志队列
func recordSysLog(opType, content string) {
	log := model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    opType,
		OpContent: content,
	}
	global.GQEQUE_LOG_DB.Enqueue(&log)
}

// diffFields 对比两条记录，返回有变化的字段 JSON 字符串
func diffFields(fields []struct{ key, label, oldV, newV string }) string {
	type Change struct {
		Field string `json:"field"`
		Label string `json:"label"`
		Old   string `json:"old"`
		New   string `json:"new"`
	}
	var changes []Change
	for _, f := range fields {
		if f.oldV != f.newV {
			changes = append(changes, Change{Field: f.key, Label: f.label, Old: f.oldV, New: f.newV})
		}
	}
	b, _ := json.Marshal(changes)
	return string(b)
}

// VerifyPasswordApi 验证应用操作密码是否正确（中间件通过即成功，无其他逻辑）
func (w *WafAppApi) VerifyPasswordApi(c *gin.Context) {
	response.OkWithData("ok", c)
}

// AddApi 新增应用
func (w *WafAppApi) AddApi(c *gin.Context) {
	var req request.WafAppAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if req.Name == "" || req.StartCmd == "" {
		response.FailWithMessage("应用名称和启动命令不能为空", c)
		return
	}
	if wafAppService.CheckIsExist(req.Name) > 0 {
		response.FailWithMessage("应用名称已存在", c)
		return
	}
	app, err := wafAppService.AddApi(req)
	if err != nil {
		response.FailWithMessage("添加失败: "+err.Error(), c)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	changes, _ := json.Marshal(map[string]string{
		"start_cmd": req.StartCmd,
		"app_dir":   app.AppDir,
		"env":       req.Env,
		"stop_cmd":  req.StopCmd,
	})
	wafAppChangeLogService.Record(app.Code, app.Name, "新增",
		fmt.Sprintf("%v", operator), fmt.Sprintf("%v", operatorIP), string(changes))
	recordSysLog("应用管理", fmt.Sprintf("新增应用 [%s] operator=%v ip=%v", app.Name, operator, operatorIP))

	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_NEW,
		Content: *app,
	}
	response.OkWithMessage("添加成功", c)
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
	var req request.WafAppEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}

	// 取旧值用于 diff
	oldApp := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	if oldApp == nil || oldApp.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}

	if err := wafAppService.ModifyApi(req); err != nil {
		response.FailWithMessage("修改失败: "+err.Error(), c)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")

	changesJSON := diffFields([]struct{ key, label, oldV, newV string }{
		{"start_cmd", "启动命令", oldApp.StartCmd, req.StartCmd},
		{"app_dir", "工作目录", oldApp.AppDir, req.AppDir},
		{"env", "环境变量", oldApp.Env, req.Env},
		{"stop_cmd", "停止命令", oldApp.StopCmd, req.StopCmd},
	})
	if changesJSON != "[]" && changesJSON != "null" {
		wafAppChangeLogService.Record(oldApp.Code, req.Name, "修改",
			fmt.Sprintf("%v", operator), fmt.Sprintf("%v", operatorIP), changesJSON)
	}
	recordSysLog("应用管理", fmt.Sprintf("修改应用 [%s] operator=%v ip=%v", req.Name, operator, operatorIP))

	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_UPDATE,
		Content: *app,
	}
	response.OkWithMessage("修改成功", c)
}

// DelApi 删除应用
func (w *WafAppApi) DelApi(c *gin.Context) {
	var req request.WafAppDelReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	if app == nil || app.Id == "" {
		response.FailWithMessage("应用不存在", c)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	recordSysLog("应用管理", fmt.Sprintf("删除应用 [%s] operator=%v ip=%v", app.Name, operator, operatorIP))

	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:       enums.ChanComTypeApp,
		OpType:     enums.OP_TYPE_DELETE,
		OldContent: *app,
	}
	response.OkWithMessage("删除成功", c)
}

// StartApi 启动应用
func (w *WafAppApi) StartApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	recordSysLog("应用管理", fmt.Sprintf("启动应用 [%s] operator=%v ip=%v", req.Code, operator, operatorIP))
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_APP_START,
		Content: req.Code,
	}
	response.OkWithMessage("启动指令已发送", c)
}

// StopApi 停止应用
func (w *WafAppApi) StopApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_APP_STOP,
		Content: req.Code,
	}
	response.OkWithMessage("停止指令已发送", c)
}

// RestartApi 重启应用
func (w *WafAppApi) RestartApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	recordSysLog("应用管理", fmt.Sprintf("重启应用 [%s] operator=%v ip=%v", req.Code, operator, operatorIP))
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_APP_RESTART,
		Content: req.Code,
	}
	response.OkWithMessage("重启指令已发送", c)
}

// GetStatusApi 查询应用运行状态
func (w *WafAppApi) GetStatusApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	rt := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetRuntimeStatus(req.Code)
	response.OkWithData(gin.H{
		"code":          rt.Code,
		"pid":           rt.Pid,
		"run_status":    rt.Status,
		"start_time":    rt.StartTime,
		"restart_count": rt.RestartCount,
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
	var req request.WafAppCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.ClearLogs(req.Code)
	response.OkWithMessage("日志已清空", c)
}

// UploadFileApi 上传文件到应用目录
func (w *WafAppApi) UploadFileApi(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, appUploadMaxBytes)
	code := c.PostForm("code")
	expectedHash := c.PostForm("hash")
	if code == "" {
		response.FailWithMessage("code 不能为空", c)
		return
	}
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		response.FailWithMessage("获取文件失败: "+err.Error(), c)
		return
	}
	defer file.Close()

	if err := wafAppService.UploadFile(code, header.Filename, file, expectedHash); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	app := wafAppService.GetDetailByCodeApi(code)
	appName := code
	if app != nil {
		appName = app.Name
	}
	changesJSON := fmt.Sprintf(`[{"field":"file","label":"上传文件","old":"","new":"%s"}]`, header.Filename)
	wafAppChangeLogService.Record(code, appName, "上传",
		fmt.Sprintf("%v", operator), fmt.Sprintf("%v", operatorIP), changesJSON)
	recordSysLog("应用管理", fmt.Sprintf("上传文件 [%s] 到应用 [%s] operator=%v ip=%v", header.Filename, appName, operator, operatorIP))

	response.OkWithMessage("上传成功", c)
}

// UpgradeApi 升级应用（停止→备份→替换→重启）
func (w *WafAppApi) UpgradeApi(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, appUploadMaxBytes)
	code := c.PostForm("code")
	expectedHash := c.PostForm("hash")
	if code == "" {
		response.FailWithMessage("code 不能为空", c)
		return
	}
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		response.FailWithMessage("获取文件失败: "+err.Error(), c)
		return
	}
	defer file.Close()

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApp(code)

	if err := wafAppService.UpgradeApp(code, header.Filename, file, expectedHash); err != nil {
		response.FailWithMessage("升级失败: "+err.Error(), c)
		_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(code)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	app := wafAppService.GetDetailByCodeApi(code)
	appName := code
	if app != nil {
		appName = app.Name
	}
	changesJSON := fmt.Sprintf(`[{"field":"file","label":"升级文件","old":"","new":"%s"}]`, header.Filename)
	wafAppChangeLogService.Record(code, appName, "升级",
		fmt.Sprintf("%v", operator), fmt.Sprintf("%v", operatorIP), changesJSON)
	recordSysLog("应用管理", fmt.Sprintf("升级应用 [%s] 文件=%s operator=%v ip=%v", appName, header.Filename, operator, operatorIP))

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(code)
	response.OkWithMessage("升级成功，应用已重新启动", c)
}

// RollbackApi 回滚应用到备份版本
func (w *WafAppApi) RollbackApi(c *gin.Context) {
	var req request.WafAppRollbackReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApp(req.Code)

	if err := wafAppService.RollbackApp(req.Code, req.Filename); err != nil {
		response.FailWithMessage("回滚失败: "+err.Error(), c)
		_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(req.Code)
		return
	}

	operator, _ := c.Get("loginAccount")
	operatorIP, _ := c.Get("loginIP")
	app := wafAppService.GetDetailByCodeApi(req.Code)
	appName := req.Code
	if app != nil {
		appName = app.Name
	}
	changesJSON := fmt.Sprintf(`[{"field":"file","label":"回滚文件","old":"","new":"%s"}]`, req.Filename)
	wafAppChangeLogService.Record(req.Code, appName, "回滚",
		fmt.Sprintf("%v", operator), fmt.Sprintf("%v", operatorIP), changesJSON)
	recordSysLog("应用管理", fmt.Sprintf("回滚应用 [%s] 备份=%s operator=%v ip=%v", appName, req.Filename, operator, operatorIP))

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(req.Code)
	response.OkWithMessage("回滚成功，应用已重新启动", c)
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
