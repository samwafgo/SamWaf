package api

import (
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

func validateHealthTest(req *request.WafHostHealthTestReq) (model.HealthyConfig, error) {
	var cfg model.HealthyConfig
	if len(req.HealthyJSON) == 0 || len(req.HealthyJSON) > 8192 || json.Unmarshal([]byte(req.HealthyJSON), &cfg) != nil {
		return cfg, errors.New("健康检测配置格式不正确")
	}
	if cfg.IsEnableHealthy < 0 || cfg.IsEnableHealthy > 1 || cfg.FailCount < 1 || cfg.FailCount > 10 || cfg.SuccessCount < 1 || cfg.SuccessCount > 10 {
		return cfg, errors.New("健康检测开关或连续次数不合法，连续次数需在1–10之间")
	}
	if cfg.ResponseTime < 1 || cfg.ResponseTime > 120 {
		return cfg, errors.New("手动测试超时时间需在1–120秒之间")
	}
	if cfg.CheckMethod != http.MethodGet && cfg.CheckMethod != http.MethodHead {
		return cfg, errors.New("检测方法仅支持GET或HEAD")
	}
	if len(cfg.CheckPath) > 2048 || strings.IndexFunc(cfg.CheckPath, unicode.IsControl) >= 0 {
		return cfg, errors.New("检测路径过长或包含无效字符")
	}
	if cfg.CheckPath != "" {
		path, err := url.ParseRequestURI(cfg.CheckPath)
		if err != nil || !strings.HasPrefix(cfg.CheckPath, "/") || strings.HasPrefix(cfg.CheckPath, "//") || strings.Contains(cfg.CheckPath, "#") || path.IsAbs() || path.Host != "" {
			return cfg, errors.New("检测路径应为以/开头的站内路径")
		}
	}
	if len(cfg.ExpectedCodes) > 512 {
		return cfg, errors.New("预期状态码列表过长")
	}
	for _, value := range strings.Split(cfg.ExpectedCodes, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		code, err := strconv.Atoi(value)
		if err != nil || len(value) != 3 || code < 100 || code > 599 {
			return cfg, errors.New("预期状态码需在100–599之间，以英文逗号分隔")
		}
	}
	if len(req.Code) > 64 || len(req.Host) > 512 || len(req.RemoteHost) > 512 || len(req.RemoteIP) > 64 || req.Offset < 0 || req.Offset > 1000000 || req.Limit < 0 || req.Limit > 5 {
		return cfg, errors.New("健康检测参数长度或分页范围不合法")
	}
	for _, value := range []string{req.Code, req.Host, req.RemoteHost, req.RemoteIP} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return cfg, errors.New("健康检测参数包含无效字符")
		}
	}
	if req.IsEnableLoadBalance < 0 || req.IsEnableLoadBalance > 1 || req.IsTransBackDomain < 0 || req.IsTransBackDomain > 1 || req.RemotePort < 1 || req.RemotePort > 65535 {
		return cfg, errors.New("回源开关或端口不合法")
	}
	if req.RemoteIP != "" && net.ParseIP(req.RemoteIP) == nil {
		return cfg, errors.New("回源IP格式不正确")
	}
	origin, err := url.Parse(req.RemoteHost)
	if err != nil || origin.Host == "" || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.RawFragment != "" || origin.Opaque != "" || origin.Port() != "" || origin.Path != "" {
		return cfg, errors.New("回源地址应为不含端口、路径或凭据的HTTP/HTTPS地址")
	}
	if req.Limit == 0 {
		req.Limit = 5
	}
	return cfg, nil
}

// TestHealthApi 使用当前编辑参数检测源站，不保存配置。
func (w *WafHostAPi) TestHealthApi(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	var req request.WafHostHealthTestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("健康检测参数解析失败", c)
		return
	}
	cfg, err := validateHealthTest(&req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	var listeners *wafenginmodel.SafeServerMap
	if engine := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE; engine != nil {
		listeners = engine.ServerOnline
	}
	result, err := waf_service.WafHealthServiceApp.Test(c.Request.Context(), req, cfg, listeners)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(result, "检测完成", c)
}
