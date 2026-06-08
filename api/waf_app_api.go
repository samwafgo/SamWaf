package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"github.com/gin-gonic/gin"
)

type WafAppApi struct{}

// AddApi 新增应用
// @Summary      新增应用
// @Description  新增一个由 SamWaf 托管的应用进程配置
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAppAddReq  true  "应用配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /application/app/add [post]
func (w *WafAppApi) AddApi(c *gin.Context) {
	var req request.WafAppAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
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
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_NEW,
		Content: *app,
	}
	response.OkWithMessage("添加成功", c)
}

// GetListApi 获取应用列表
// @Summary      获取应用列表
// @Description  分页查询所有托管应用，返回列表及实时运行状态（RunStatus / PID / 重启次数）
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAppSearchReq  true  "分页参数"
// @Success      200   {object}  response.Response{data=object}  "查询成功，data.list 为应用列表，data.total 为总数"
// @Security     ApiKeyAuth
// @Router       /application/app/list [post]
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

	// 附加运行时状态
	type AppWithStatus struct {
		Id              string `json:"id"`
		Code            string `json:"code"`
		Name            string `json:"name"`
		AppDir          string `json:"app_dir"`
		StartCmd        string `json:"start_cmd"`
		AutoStart       int    `json:"auto_start"`
		StartStatus     int    `json:"start_status"`
		StopMode        string `json:"stop_mode"`
		StopTimeout     int    `json:"stop_timeout"`
		RestartPolicy   string `json:"restart_policy"`
		RestartDelay    int    `json:"restart_delay"`
		MaxRestartCount int    `json:"max_restart_count"`
		LogMaxLines     int    `json:"log_max_lines"`
		Remarks         string `json:"remarks"`
		RunStatus       int    `json:"run_status"`
		Pid             int    `json:"pid"`
		RestartCount    int    `json:"restart_count"`
	}

	result := make([]AppWithStatus, 0, len(list))
	for _, app := range list {
		rt := globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.GetRuntimeStatus(app.Code)
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
		})
	}
	response.OkWithDetailed(gin.H{"list": result, "total": total}, "查询成功", c)
}

// GetDetailApi 获取应用详情
// @Summary      获取应用详情
// @Description  根据 id 获取单个应用的完整配置信息
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "应用 ID"
// @Success      200  {object}  response.Response{data=model.WafApp}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /application/app/detail [get]
func (w *WafAppApi) GetDetailApi(c *gin.Context) {
	var req request.WafAppDetailReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithData(wafAppService.GetDetailApi(req), c)
}

// ModifyApi 修改应用配置
// @Summary      修改应用配置
// @Description  修改已有应用的配置，若应用正在运行则自动重启
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAppEditReq  true  "应用配置（含 id）"
// @Success      200   {object}  response.Response  "修改成功"
// @Security     ApiKeyAuth
// @Router       /application/app/edit [post]
func (w *WafAppApi) ModifyApi(c *gin.Context) {
	var req request.WafAppEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAppService.ModifyApi(req); err != nil {
		response.FailWithMessage("修改失败: "+err.Error(), c)
		return
	}
	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_UPDATE,
		Content: *app,
	}
	response.OkWithMessage("修改成功", c)
}

// DelApi 删除应用
// @Summary      删除应用
// @Description  删除应用配置，若进程正在运行则先停止再删除
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "应用 ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /application/app/del [get]
func (w *WafAppApi) DelApi(c *gin.Context) {
	var req request.WafAppDelReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	app := wafAppService.GetDetailApi(request.WafAppDetailReq{Id: req.Id})
	if err := wafAppService.DelApi(req); err != nil {
		response.FailWithMessage("删除失败", c)
		return
	}
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:       enums.ChanComTypeApp,
		OpType:     enums.OP_TYPE_DELETE,
		OldContent: *app,
	}
	response.OkWithMessage("删除成功", c)
}

// StartApi 启动应用
// @Summary      启动应用
// @Description  向引擎发送启动指令（异步），使用 /application/app/status 接口轮询确认启动结果
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response  "启动指令已发送"
// @Security     ApiKeyAuth
// @Router       /application/app/start [get]
func (w *WafAppApi) StartApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_APP_START,
		Content: req.Code,
	}
	response.OkWithMessage("启动指令已发送", c)
}

// StopApi 停止应用
// @Summary      停止应用
// @Description  向引擎发送停止指令（异步），使用 /application/app/status 接口轮询确认停止结果
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response  "停止指令已发送"
// @Security     ApiKeyAuth
// @Router       /application/app/stop [get]
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
// @Summary      重启应用
// @Description  向引擎发送重启指令（异步），使用 /application/app/status 接口轮询确认重启结果
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response  "重启指令已发送"
// @Security     ApiKeyAuth
// @Router       /application/app/restart [get]
func (w *WafAppApi) RestartApi(c *gin.Context) {
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type:    enums.ChanComTypeApp,
		OpType:  enums.OP_TYPE_APP_RESTART,
		Content: req.Code,
	}
	response.OkWithMessage("重启指令已发送", c)
}

// GetStatusApi 查询应用运行状态
// @Summary      查询应用运行状态
// @Description  实时查询应用进程的运行状态（同步），run_status: 0=已停止 1=运行中 2=已崩溃
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response{data=object}  "查询成功，data 含 pid/run_status/start_time/restart_count"
// @Security     ApiKeyAuth
// @Router       /application/app/status [get]
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
// @Summary      获取应用日志
// @Description  获取应用进程最近的 stdout/stderr 日志（内存中最多 LogMaxLines 行）
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response{data=object}  "查询成功，data.logs 为字符串数组"
// @Security     ApiKeyAuth
// @Router       /application/app/logs [get]
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
// @Summary      清空应用日志
// @Description  清空应用的内存日志及磁盘日志文件（{AppDir}/app.log）
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAppCodeReq  true  "应用唯一编码"
// @Success      200   {object}  response.Response  "日志已清空"
// @Security     ApiKeyAuth
// @Router       /application/app/clearlogs [post]
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
// @Summary      上传文件到应用目录
// @Description  上传文件到应用工作目录（不升级，不重启），可选 SHA256 哈希校验
// @Tags         应用管理
// @Accept       multipart/form-data
// @Produce      json
// @Param        code  formData  string  true   "应用唯一编码"
// @Param        hash  formData  string  false  "文件 SHA256 哈希值（可选，不传则跳过校验）"
// @Param        file  formData  file    true   "上传的文件"
// @Success      200   {object}  response.Response  "上传成功"
// @Security     ApiKeyAuth
// @Router       /application/app/upload [post]
func (w *WafAppApi) UploadFileApi(c *gin.Context) {
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
	response.OkWithMessage("上传成功", c)
}

// UpgradeApi 升级应用（停止→备份→替换→重启）
// @Summary      升级应用
// @Description  同步执行升级流程：停止应用→备份旧文件→上传新文件（含 SHA256 校验）→重启应用。因需等待进程退出，请适当设置客户端超时
// @Tags         应用管理
// @Accept       multipart/form-data
// @Produce      json
// @Param        code  formData  string  true   "应用唯一编码"
// @Param        hash  formData  string  false  "文件 SHA256 哈希值（可选，不传则跳过校验）"
// @Param        file  formData  file    true   "新版本文件"
// @Success      200   {object}  response.Response  "升级成功，应用已重新启动"
// @Security     ApiKeyAuth
// @Router       /application/app/upgrade [post]
func (w *WafAppApi) UpgradeApi(c *gin.Context) {
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

	// 同步停止，等进程真正退出后才能替换文件（Windows 不允许覆盖运行中的可执行文件）
	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApp(code)

	if err := wafAppService.UpgradeApp(code, header.Filename, file, expectedHash); err != nil {
		response.FailWithMessage("升级失败: "+err.Error(), c)
		// 升级失败也尝试恢复启动
		_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(code)
		return
	}

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(code)
	response.OkWithMessage("升级成功，应用已重新启动", c)
}

// RollbackApi 回滚应用到备份版本
// @Summary      回滚应用
// @Description  同步执行回滚流程：停止应用→从备份文件恢复→重启应用
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code      query     string  true  "应用唯一编码"
// @Param        filename  query     string  true  "备份文件名（从备份列表接口获取）"
// @Success      200       {object}  response.Response  "回滚成功，应用已重新启动"
// @Security     ApiKeyAuth
// @Router       /application/app/rollback [get]
func (w *WafAppApi) RollbackApi(c *gin.Context) {
	var req request.WafAppRollbackReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	// 同步停止，等进程真正退出后才能覆盖文件
	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StopApp(req.Code)

	if err := wafAppService.RollbackApp(req.Code, req.Filename); err != nil {
		response.FailWithMessage("回滚失败: "+err.Error(), c)
		_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(req.Code)
		return
	}

	_ = globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE.StartApp(req.Code)
	response.OkWithMessage("回滚成功，应用已重新启动", c)
}

// GetBackupsApi 获取备份文件列表
// @Summary      获取备份文件列表
// @Description  列出应用工作目录下 backup/ 子目录中的所有备份文件，包含文件名、大小和备份时间
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response{data=object}  "查询成功，data.list 为 BackupInfo 数组"
// @Security     ApiKeyAuth
// @Router       /application/app/backups [get]
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
// @Summary      查询应用端口与连接 IP
// @Description  查询应用进程树（含子进程）当前占用的端口及建立的 TCP 连接，结果缓存 30 秒，最多返回 1000 条连接记录
// @Tags         应用管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "应用唯一编码"
// @Success      200   {object}  response.Response{data=wafappmodel.NetStatsResult}  "查询成功"
// @Security     ApiKeyAuth
// @Router       /application/app/network [get]
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
