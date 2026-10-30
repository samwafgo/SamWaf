package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const logExportBodyLimit = 16 << 10

var logExportIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var logExportTicketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

type WafLogExportAPI struct{}

func logExportActor(c *gin.Context) waf_service.LogExportActor {
	return waf_service.LogExportActor{
		LoginAccount: c.GetString("loginAccount"),
		UserRole:     c.GetString("userRole"),
		IsOpenAPI:    c.GetBool("is_openapi"),
		ClientIP:     utils.GetManageClientIP(c),
	}
}

func logExportFailure(c *gin.Context, err error) {
	code, message := "EXPORT_FAILED", "日志导出操作未完成，请稍后重试"
	var exportErr *waf_service.LogExportError
	if errors.As(err, &exportErr) {
		code, message = exportErr.Code, exportErr.Message
	}
	resultCode := response.ERROR
	if code == "EXPORT_DISABLED" {
		resultCode = response.EXPORT_DISABLED
	}
	if code == "EXPORT_FORBIDDEN" || code == "FORBIDDEN" {
		resultCode = response.FORBIDDEN
	}
	response.Result(resultCode, gin.H{"error_code": code}, message, c)
}

func logExportInvalid(c *gin.Context, message string) {
	response.FailWithDetailed(gin.H{"error_code": "EXPORT_INVALID_REQUEST"}, message, c)
}

func validLogExportID(c *gin.Context) (string, bool) {
	id := c.Param("id")
	if !logExportIDPattern.MatchString(id) {
		logExportInvalid(c, "导出任务编号格式不正确")
		return "", false
	}
	return id, true
}

func decodeLogExportCreate(c *gin.Context) (request.LogExportCreateReq, error) {
	var req request.LogExportCreateReq
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, logExportBodyLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("导出参数必须为不超过16KiB的JSON对象，且不能包含未知字段")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return req, fmt.Errorf("请求只能包含一个JSON对象")
	}
	if req.RequestID == "" || !logRequestIDPattern.MatchString(req.RequestID) {
		return req, fmt.Errorf("request_id须为1至64位字母、数字或分隔符")
	}
	if req.Format == "" {
		req.Format = "jsonl"
	}
	switch req.Format {
	case "jsonl", "csv", "sqlite":
	default:
		return req, fmt.Errorf("不支持的导出格式")
	}
	if req.Tables == nil {
		req.Tables = []string{"access_log", "security_event"}
	}
	if len(req.Tables) < 1 || len(req.Tables) > 2 {
		return req, fmt.Errorf("请选择一至两张日志表")
	}
	seen := make(map[string]bool, 2)
	for _, table := range req.Tables {
		if (table != "access_log" && table != "security_event") || seen[table] {
			return req, fmt.Errorf("日志表选择无效或重复")
		}
		seen[table] = true
	}
	if len(req.StartTime) > 64 || len(req.EndTime) > 64 {
		return req, fmt.Errorf("时间参数过长")
	}
	now := time.Now()
	switch req.RangeMode {
	case "", "recent":
		if req.StartTime != "" || req.EndTime != "" {
			return req, fmt.Errorf("最近4小时模式不接受自定义时间")
		}
		req.RangeMode = "recent"
		req.StartTime = now.Add(-4 * time.Hour).Format(time.RFC3339Nano)
		req.EndTime = now.Format(time.RFC3339Nano)
	case "all":
		if req.StartTime != "" || req.EndTime != "" {
			return req, fmt.Errorf("全部日志模式不接受自定义时间")
		}
		req.EndTime = now.Format(time.RFC3339Nano)
	case "custom":
		start, errStart := time.Parse(time.RFC3339Nano, req.StartTime)
		end, errEnd := time.Parse(time.RFC3339Nano, req.EndTime)
		if errStart != nil || errEnd != nil || !start.Before(end) {
			return req, fmt.Errorf("自定义时间须为带时区的RFC3339，且开始时间早于结束时间")
		}
	default:
		return req, fmt.Errorf("不支持的时间范围模式")
	}
	return req, nil
}

func (WafLogExportAPI) Capabilities(c *gin.Context) {
	result, err := waf_service.WafLogExportServiceApp.Capabilities(c.Request.Context(), logExportActor(c))
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) Create(c *gin.Context) {
	req, err := decodeLogExportCreate(c)
	if err != nil {
		logExportInvalid(c, err.Error())
		return
	}
	result, err := waf_service.WafLogExportServiceApp.Create(c.Request.Context(), logExportActor(c), req)
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) List(c *gin.Context) {
	var req request.LogExportListReq
	page := c.Query("page")
	if page == "" {
		page = c.Query("page_index")
	}
	if page != "" {
		value, err := strconv.Atoi(page)
		if err != nil {
			logExportInvalid(c, "分页参数格式不正确")
			return
		}
		req.PageIndex = value
	}
	pageSize := c.Query("page_size")
	if pageSize == "" {
		pageSize = c.Query("pageSize")
	}
	if pageSize != "" {
		value, err := strconv.Atoi(pageSize)
		if err != nil {
			logExportInvalid(c, "分页参数格式不正确")
			return
		}
		req.PageSize = value
	}
	req.SortBy = c.Query("sort_by")
	req.SortOrder = c.Query("sort_order")
	if req.PageIndex == 0 {
		req.PageIndex = 1
	}
	if req.PageSize == 0 {
		req.PageSize = 20
	}
	if req.PageIndex < 1 || req.PageIndex > 1000000 || req.PageSize < 1 || req.PageSize > 100 {
		logExportInvalid(c, "分页参数超出范围")
		return
	}
	if req.SortBy == "" {
		req.SortBy = "created_at"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}
	if (req.SortBy != "created_at" && req.SortBy != "expires_at" && req.SortBy != "status") || (req.SortOrder != "asc" && req.SortOrder != "desc") {
		logExportInvalid(c, "排序参数不正确")
		return
	}
	result, err := waf_service.WafLogExportServiceApp.List(c.Request.Context(), logExportActor(c), req)
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) Get(c *gin.Context) {
	id, ok := validLogExportID(c)
	if !ok {
		return
	}
	result, err := waf_service.WafLogExportServiceApp.Get(c.Request.Context(), logExportActor(c), id)
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) Cancel(c *gin.Context) {
	id, ok := validLogExportID(c)
	if !ok {
		return
	}
	result, err := waf_service.WafLogExportServiceApp.Cancel(c.Request.Context(), logExportActor(c), id)
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) Delete(c *gin.Context) {
	id, ok := validLogExportID(c)
	if !ok {
		return
	}
	if err := waf_service.WafLogExportServiceApp.Delete(c.Request.Context(), logExportActor(c), id); err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithMessage("删除请求已处理，活动任务及下载结束后回收产物", c)
}

func (WafLogExportAPI) DownloadTicket(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	id, ok := validLogExportID(c)
	if !ok {
		return
	}
	result, err := waf_service.WafLogExportServiceApp.IssueDownloadTicket(c.Request.Context(), logExportActor(c), id)
	if err != nil {
		logExportFailure(c, err)
		return
	}
	response.OkWithData(result, c)
}

func (WafLogExportAPI) Download(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("Accept-Ranges", "none")
	c.Header("X-Content-Type-Options", "nosniff")
	id := c.Param("id")
	var req request.LogExportDownloadReq
	if err := c.ShouldBindQuery(&req); err != nil || !logExportIDPattern.MatchString(id) || !logExportTicketPattern.MatchString(req.Ticket) {
		c.JSON(http.StatusBadRequest, gin.H{"error_code": "EXPORT_INVALID_REQUEST", "message": "下载参数不正确"})
		return
	}
	if c.GetHeader("Range") != "" {
		c.JSON(http.StatusRequestedRangeNotSatisfiable, gin.H{"error_code": "EXPORT_RANGE_UNSUPPORTED", "message": "日志包须整包下载，请重新申请下载票据"})
		return
	}
	download, err := waf_service.WafLogExportServiceApp.OpenDownload(c.Request.Context(), id, req.Ticket, utils.GetManageClientIP(c))
	if err != nil {
		status, code, message := http.StatusInternalServerError, "EXPORT_FAILED", "日志包下载未完成"
		var exportErr *waf_service.LogExportError
		if errors.As(err, &exportErr) {
			status, code, message = exportErr.HTTPStatus, exportErr.Code, exportErr.Message
		}
		if status < 400 || status > 599 {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error_code": code, "message": message})
		return
	}
	streamLogExportDownload(c, id, download)
}

func streamLogExportDownload(c *gin.Context, id string, download *waf_service.LogExportDownload) {
	var transferErr error
	defer func() {
		closeErr := download.Reader.Close()
		if transferErr == nil {
			transferErr = closeErr
		}
		if download.Complete != nil {
			download.Complete(transferErr)
		}
	}()
	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", `attachment; filename="samwaf_logs_`+id+`.zip"`)
	if download.Size >= 0 {
		c.Header("Content-Length", strconv.FormatInt(download.Size, 10))
	}
	c.Status(http.StatusOK)
	written, err := io.Copy(c.Writer, download.Reader)
	transferErr = err
	if transferErr == nil && download.Size >= 0 && written != download.Size {
		transferErr = io.ErrUnexpectedEOF
	}
	if transferErr == nil {
		transferErr = c.Request.Context().Err()
	}
}
