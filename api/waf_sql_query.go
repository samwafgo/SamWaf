package api

import (
	"SamWaf/common/zlog"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"fmt"

	"github.com/gin-gonic/gin"
)

type WafSqlQueryApi struct {
}

func (w *WafSqlQueryApi) ExecuteQueryApi(c *gin.Context) {
	var req request.WafSqlQueryReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}

	// 审计上下文：操作者账号 / IP（由 auth 中间件写入）
	account := c.GetString("loginAccount")
	ip := c.GetString("loginIP")

	result, err := wafSqlQueryService.ExecuteQuery(req)
	if err != nil {
		// 被拒的查询（含命中敏感表/列、非法运算符等）记 Warn，便于发现探测行为
		zlog.Warn("SqlQueryAudit", fmt.Sprintf(
			"rejected account=%s ip=%s db=%s table=%s mode=%s err=%s",
			account, ip, req.DbType, req.Table, req.Mode, err.Error()))
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}

	zlog.Info("SqlQueryAudit", fmt.Sprintf(
		"ok account=%s ip=%s db=%s table=%s mode=%s columns=%v top=%d rows=%d",
		account, ip, req.DbType, req.Table, result.Mode, req.Columns, req.Top, result.Total))
	response.OkWithDetailed(result, "查询成功", c)
}

func (w *WafSqlQueryApi) GetTableInfoApi(c *gin.Context) {
	var req request.WafDbTableInfoReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("参数解析失败: "+err.Error(), c)
		return
	}
	result, err := wafSqlQueryService.GetTableInfo(req)
	if err != nil {
		response.FailWithMessage("获取表信息失败: "+err.Error(), c)
	} else {
		response.OkWithDetailed(result, "获取成功", c)
	}
}

// GetQueryableSchemaApi 返回可查表及其可见列，供前端向导下拉使用（不含敏感表/敏感列）。
func (w *WafSqlQueryApi) GetQueryableSchemaApi(c *gin.Context) {
	var req request.WafDbTableInfoReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("参数解析失败: "+err.Error(), c)
		return
	}
	result, err := wafSqlQueryService.GetQueryableSchema(req)
	if err != nil {
		response.FailWithMessage("获取可查询结构失败: "+err.Error(), c)
	} else {
		response.OkWithDetailed(result, "获取成功", c)
	}
}
