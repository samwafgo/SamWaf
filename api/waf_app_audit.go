package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafapppath"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

type appLifecycle interface {
	StartApp(string) error
	StopApp(string) error
}

func (w *WafAppApi) fileEngine() appLifecycle {
	if w.lifecycle != nil {
		return w.lifecycle
	}
	return globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE
}

type appAudit struct {
	event, code, name, filename string
	stage                       string
	result                      int
}

func newAppAudit(event string) *appAudit {
	return &appAudit{event: event, stage: "bind", result: model.AccessAuditFail}
}

func (a *appAudit) app(app *model.WafApp) {
	if app != nil && app.Id != "" {
		a.code, a.name = app.Code, app.Name
	}
}

func (a *appAudit) ok(stage string) {
	a.stage, a.result = stage, model.AccessAuditOK
}

func appAuditText(s string, limit int) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func appSafeFilename(filename string) string {
	if filename == "" {
		return ""
	}
	return filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
}

func (a *appAudit) write(c *gin.Context) {
	waf_service.WafSecurityAuditServiceApp.Write(waf_service.AuditEntry{
		Event: a.event, AccountName: c.GetString("loginAccount"),
		ClientIP: utils.GetManageClientIP(c), URL: c.Request.URL.Path,
		Result: a.result,
		Message: fmt.Sprintf("stage=%s result=%d app=%q name=%q file=%q", a.stage, a.result,
			appAuditText(a.code, 64), appAuditText(a.name, 100), appAuditText(appSafeFilename(a.filename), 100)),
	})
}

func (w *WafAppApi) submitAppOperation(c *gin.Context, event string, op int, message string) {
	audit := newAppAudit(event)
	defer audit.write(c)
	var req request.WafAppCodeReq
	if err := c.ShouldBindQuery(&req); err != nil {
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
	audit.stage = "submit"
	global.GWAF_CHAN_COMMON_MSG <- spec.ChanCommon{
		Type: enums.ChanComTypeApp, OpType: op, Content: req.Code,
	}
	audit.ok("submitted")
	response.OkWithMessage(message, c)
}

type appChange struct {
	Field string `json:"field"`
	Label string `json:"label"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

func appChangesJSON(changes []appChange) string {
	if changes == nil {
		changes = []appChange{}
	}
	b, _ := json.Marshal(changes)
	return string(b)
}

func recordAppFileChange(c *gin.Context, a *appAudit, operation, label string) {
	wafAppChangeLogService.Record(a.code, a.name, operation,
		c.GetString("loginAccount"), utils.GetManageClientIP(c), appChangesJSON([]appChange{
			{Field: "file", Label: label, New: appSafeFilename(a.filename)},
		}))
}

// diffFields 记录字段变更；工作目录保留新旧值，命令与环境变量只记录摘要。
func diffFields(fields []struct{ key, label, oldV, newV string }) string {
	changes := make([]appChange, 0, len(fields))
	for _, f := range fields {
		if f.oldV == f.newV {
			continue
		}
		change := appChange{Field: f.key, Label: f.label, New: "已更新"}
		if f.key == "app_dir" {
			change.Old, change.New = f.oldV, f.newV
		}
		changes = append(changes, change)
	}
	return appChangesJSON(changes)
}
