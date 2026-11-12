package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafreport"
	"github.com/gin-gonic/gin"
)

type WafReportAPI struct{}

func reportActor(c *gin.Context) waf_service.ReportActor {
	return waf_service.ReportActor{LoginAccount: c.GetString("loginAccount"), UserRole: c.GetString("userRole"), ClientIP: utils.GetManageClientIP(c), IsOpenAPI: c.GetBool("is_openapi")}
}
func reportFailure(c *gin.Context, err error) {
	if errors.Is(err, waf_service.ErrReportForbidden) {
		response.Result(response.FORBIDDEN, nil, err.Error(), c)
		return
	}
	response.FailWithMessage(err.Error(), c)
}
func decodeReportBody(c *gin.Context, v interface{}) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<10)
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("请求须为不超过8KiB的JSON对象，且不得包含未知字段")
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("请求只能包含一个JSON对象")
	}
	return nil
}
func (WafReportAPI) Config(c *gin.Context) {
	v, err := waf_service.WafReportServiceApp.Config(c.Request.Context(), reportActor(c))
	if err != nil {
		reportFailure(c, err)
		return
	}
	response.OkWithData(v, c)
}
func (WafReportAPI) Save(c *gin.Context) {
	var cfg *wafreport.Config
	if err := decodeReportBody(c, &cfg); err != nil {
		reportFailure(c, err)
		return
	}
	if cfg == nil {
		reportFailure(c, errors.New("配置不能为空"))
		return
	}
	if err := cfg.Validate(); err != nil {
		reportFailure(c, err)
		return
	}
	if err := waf_service.WafReportServiceApp.SaveConfig(c.Request.Context(), reportActor(c), *cfg); err != nil {
		reportFailure(c, err)
		return
	}
	response.OkWithMessage("报告配置已保存", c)
}
func (WafReportAPI) List(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("pageIndex", "1"))
	if err != nil {
		reportFailure(c, errors.New("分页参数不正确"))
		return
	}
	size, err := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	if err != nil || page < 1 || page > 1000000 || size < 1 || size > 100 {
		reportFailure(c, errors.New("分页参数超出范围"))
		return
	}
	v, err := waf_service.WafReportServiceApp.List(c.Request.Context(), reportActor(c), page, size)
	if err != nil {
		reportFailure(c, err)
		return
	}
	response.OkWithData(v, c)
}
func (WafReportAPI) Create(c *gin.Context) {
	var req struct {
		Kind string `json:"kind"`
		Date string `json:"date"`
	}
	if err := decodeReportBody(c, &req); err != nil {
		reportFailure(c, err)
		return
	}
	if req.Kind != "daily" && req.Kind != "weekly" && req.Kind != "monthly" {
		reportFailure(c, errors.New("报告类型不正确"))
		return
	}
	if len(req.Date) != 10 {
		reportFailure(c, errors.New("日期须为 YYYY-MM-DD"))
		return
	}
	date, err := time.ParseInLocation("2006-01-02", req.Date, time.Local)
	if err != nil {
		reportFailure(c, errors.New("日期须为 YYYY-MM-DD"))
		return
	}
	r, err := wafreport.NewRange(wafreport.Kind(req.Kind), date)
	if err != nil || r.End.After(time.Now()) || r.Start.Year() < 2000 {
		reportFailure(c, errors.New("请选择已结束的自然日、周或月"))
		return
	}
	v, err := waf_service.WafReportServiceApp.Create(c.Request.Context(), reportActor(c), req.Kind, req.Date)
	if err != nil {
		reportFailure(c, err)
		return
	}
	response.OkWithData(v, c)
}
func reportBodyID(c *gin.Context) (string, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeReportBody(c, &req); err != nil {
		return "", err
	}
	if len(req.ID) < 16 || len(req.ID) > 64 {
		return "", errors.New("报告编号不正确")
	}
	for _, v := range req.ID {
		if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '-' || v == '_') {
			return "", errors.New("报告编号不正确")
		}
	}
	return req.ID, nil
}
func (WafReportAPI) Delete(c *gin.Context) {
	id, err := reportBodyID(c)
	if err == nil {
		err = waf_service.WafReportServiceApp.Delete(c.Request.Context(), reportActor(c), id)
	}
	if err != nil {
		reportFailure(c, err)
		return
	}
	response.OkWithMessage("报告已删除", c)
}
func (WafReportAPI) Download(c *gin.Context) {
	id, err := reportBodyID(c)
	if err != nil {
		reportFailure(c, err)
		return
	}
	b, err := waf_service.WafReportServiceApp.Download(c.Request.Context(), reportActor(c), id)
	if err != nil {
		reportFailure(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")
	c.Header("Content-Disposition", "attachment; filename=\"security-report-"+id+".html\"")
	c.Data(http.StatusOK, "text/html; charset=utf-8", b)
}
