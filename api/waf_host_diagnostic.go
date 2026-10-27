package api

import (
	"SamWaf/globalobj"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http/httpguts"
)

func validateWebsiteDiagnostic(req *request.WafHostDiagnosticReq) error {
	if req.HostCode == "" || len(req.HostCode) > 64 || strings.IndexFunc(req.HostCode, unicode.IsControl) >= 0 {
		return errors.New("请选择已保存的网站")
	}
	switch req.Phase {
	case "inspect", "local_ingress", "origin", "access_url":
	default:
		return errors.New("诊断阶段不合法")
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return errors.New("诊断仅支持GET或HEAD")
	}
	if req.OriginCursor < 0 || req.OriginCursor > 1000000 || len(req.ConfigFingerprint) > 64 {
		return errors.New("诊断分页或配置标识不合法")
	}
	if req.Phase != "inspect" && len(req.ConfigFingerprint) != 64 {
		return errors.New("请先检查配置，再执行网络诊断")
	}
	if req.VisitorURL == "" {
		if req.Phase != "inspect" {
			return errors.New("请填写实际访问网址")
		}
	} else {
		if len(req.VisitorURL) > 4096 || strings.IndexFunc(req.VisitorURL, unicode.IsControl) >= 0 {
			return errors.New("访问网址过长或包含无效字符")
		}
		u, err := url.Parse(req.VisitorURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || strings.Contains(req.VisitorURL, "#") || u.Opaque != "" {
			return errors.New("请填写不含账号密码及片段的HTTP/HTTPS网址")
		}
		if strings.ContainsAny(u.Hostname(), "* \\") || strings.HasSuffix(u.Host, ":") {
			return errors.New("请填写实际访问域名或IP")
		}
		if p := u.Port(); p != "" {
			port, err := strconv.Atoi(p)
			if err != nil || port < 1 || port > 65535 {
				return errors.New("访问端口需在1–65535之间")
			}
		}
	}
	if len(req.Headers) > 20 {
		return errors.New("自定义请求头最多20项")
	}
	total := 0
	for _, h := range req.Headers {
		total += len(h.Name) + len(h.Value)
		if len(h.Name) > 128 || len(h.Value) > 2048 || !httpguts.ValidHeaderFieldName(h.Name) || !httpguts.ValidHeaderFieldValue(h.Value) || strings.IndexFunc(h.Value, unicode.IsControl) >= 0 {
			return errors.New("自定义请求头名称或值不合法")
		}
		switch strings.ToLower(h.Name) {
		case "host", "content-length", "transfer-encoding", "connection", "upgrade", "trailer", "te", "keep-alive", "expect":
			return errors.New("不能覆盖连接或传输控制请求头")
		}
		if strings.HasPrefix(strings.ToLower(h.Name), "proxy-") || strings.HasPrefix(strings.ToLower(h.Name), "x-waf-") {
			return errors.New("不能设置代理或内部控制请求头")
		}
	}
	if total > 8192 {
		return errors.New("自定义请求头总长度不能超过8KiB")
	}
	return nil
}

func (w *WafHostAPi) DiagnosticApi(c *gin.Context) {
	// 诊断会发起真实网络探测，仅面向登录用户；OpenAPI Key 走独立授权体系，统一不受理
	if isOpenApi, ok := c.Get("is_openapi"); ok {
		if b, _ := isOpenApi.(bool); b {
			response.FailWithMessage("诊断功能仅支持登录用户调用", c)
			return
		}
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	var req request.WafHostDiagnosticReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("网站诊断参数解析失败", c)
		return
	}
	if err := validateWebsiteDiagnostic(&req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	env := waf_service.WebsiteDiagnosticEnvironment{}
	if engine := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE; engine != nil {
		env.Snapshot = engine.DiagnosticSnapshot
		env.Listeners = engine.ServerOnline
	}
	result, err := waf_service.WafHostDiagnosticServiceApp.Diagnose(c.Request.Context(), req, env)
	if err != nil {
		response.FailWithDetailed(result, err.Error(), c)
		return
	}
	response.OkWithDetailed(result, "诊断完成", c)
}
