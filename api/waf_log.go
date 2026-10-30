package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafdb"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

type WafLogAPi struct {
}

var logRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

func normalizeLogRequestID(value string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" && !required {
		return "", nil
	}
	if !logRequestIDPattern.MatchString(value) {
		return "", fmt.Errorf("访问识别码格式不正确（需为 1–64 位字母、数字或分隔符）")
	}
	return value, nil
}

// GetDetailApi 获取攻击日志详情
// @Summary      获取攻击日志详情
// @Description  根据 req_uuid 获取单条攻击日志详情（含请求体、响应体）
// @Tags         日志-攻击日志
// @Accept       json
// @Produce      json
// @Param        req_uuid         query  string  true   "请求UUID"
// @Param        current_db_name  query  string  false  "数据库名称，默认 local_log"
// @Param        output_format    query  string  false  "输出格式：raw 或 curl"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /waflog/attack/detail [get]
func (w *WafLogAPi) GetDetailApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		req.REQ_UUID, err = normalizeLogRequestID(req.REQ_UUID, true)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		wafLog, err := wafLogService.GetDetailApi(req)
		if err != nil {
			response.FailWithMessage("获取日志详情失败:"+err.Error(), c)
			return
		}
		response.OkWithDetailed(wafLog, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取攻击日志列表
// @Summary      获取攻击日志列表
// @Description  分页查询攻击日志，支持按主机码、规则、IP、URL关键字、时间范围等过滤
// @Tags         日志-攻击日志
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafAttackLogSearch  true  "查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /waflog/attack/list [post]
func (w *WafLogAPi) GetListApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		req.ReqUuid, err = normalizeLogRequestID(req.ReqUuid, false)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		wafLogs, total, meta, err2 := wafLogService.GetListApiWithMeta(req)
		if err2 != nil {
			response.FailWithMessage("访问列表失败:"+err2.Error(), c)
		} else {
			// 除了列表本身，还要告诉前端这次到底查了哪些分区：
			// 自动模式下用户没选分区，界面得能说明数据是从哪来的、识别码是在哪找到的
			response.OkWithDetailed(gin.H{
				"list":             wafLogs,
				"total":            total,
				"pageIndex":        req.PageIndex,
				"pageSize":         req.PageSize,
				"shards":           meta.Shards,
				"found_in":         meta.FoundIn,
				"scanned":          meta.Scanned,
				"uuid_lookup":      meta.UuidLookup,
				"sort_forced_time": meta.SortForcedTime,
				"partial":          meta.Partial,
				"took_ms":          meta.TookMs,
				"issues":           meta.Issues,
			}, "获取成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLogAPi) ExportDBApi(c *gin.Context) {
	logExportAPIChanged(c)
}

func (w *WafLogAPi) DownloadApi(c *gin.Context) {
	logExportAPIChanged(c)
}

func logExportAPIChanged(c *gin.Context) {
	response.FailWithDetailed(gin.H{"error_code": "EXPORT_API_CHANGED"},
		"日志导出接口已更新，请升级管理端后通过导出任务创建和下载日志包", c)
}
func (w *WafLogAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, _ := wafLogService.GetListByHostCodeApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafLogs,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafLogAPi) GetAllShareDbApi(c *gin.Context) {
	wafShareList, _ := wafShareDbService.GetAllShareDbWithTiers()
	liveName := wafdb.LiveLogName()                                     // 当前驱动的实时分片标识，用于标记默认选中项
	allShareDbRep := make([]response2.AllShareDbRep, len(wafShareList)) // 创建数组
	for i, _ := range wafShareList {

		allShareDbRep[i] = response2.AllShareDbRep{
			StartTime: wafShareList[i].StartTime,
			EndTime:   wafShareList[i].EndTime,
			FileName:  wafShareList[i].FileName,
			Cnt:       wafShareList[i].Cnt,
			IsCurrent: wafShareList[i].FileName == liveName,
			PeriodKey: wafShareList[i].PeriodKey,
			Tiers:     wafShareList[i].Tiers,
			Missing:   wafShareList[i].Missing,
		}

	}
	response.OkWithDetailed(allShareDbRep, "获取成功", c)
}

// DelShardApi 主动删除一个归档分区（不看保留期）。
//
// 以前想立刻腾空间只能去「文件管理」删 .db 文件——那条路只对 SQLite 有效，
// 而且删完 share_dbs 记录还在，归档下拉里会留着一个已经不存在的分区。
// 这里按分区删：文件型删文件、服务型丢表，两边都把记录与计数缓存一并清掉。
func (w *WafLogAPi) DelShardApi(c *gin.Context) {
	var req struct {
		FileName string `json:"file_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if global.GDATA_CURRENT_CHANGE {
		response.FailWithMessage("正在切换数据库请等待", c)
		return
	}
	detail, err := wafShareDbService.ForceDeleteShard(req.FileName)
	if err != nil {
		response.FailWithMessage("删除分区失败："+err.Error(), c)
		return
	}
	response.OkWithMessage(detail, c)
}

// http 原始请求并进行脱敏处理
func (w *WafLogAPi) GetHttpCopyMaskApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		req.REQ_UUID, err = normalizeLogRequestID(req.REQ_UUID, true)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		wafLog, err := wafLogService.GetDetailApi(req)
		if err != nil {
			response.FailWithMessage("获取日志详情失败:"+err.Error(), c)
			return
		}

		if req.OutputFormat == "curl" {
			response.OkWithDetailed(GenerateCurlRequest(wafLog), "获取成功", c)
		} else {
			response.OkWithDetailed(GenerateRawHTTPRequest(wafLog), "获取成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetIPTagDBStatusApi 报告 IP 标签的当前归属库与合并进度。
// 切换归属会把另一个库里的历史标签并过来，量大时要跑一会儿，
// 页面据此显示「合并中」并在合并结束后重新拉取列表。
func (w *WafLogAPi) GetIPTagDBStatusApi(c *gin.Context) {
	response.OkWithData(gin.H{
		"db":      global.GDATA_IP_TAG_DB,
		"merging": atomic.LoadInt32(&global.GDATA_IP_TAG_MERGING) == 1,
	}, c)
}

// GetAttackIPListApi 获取风险数据列表
func (w *WafLogAPi) GetAttackIPListApi(c *gin.Context) {
	var req request.WafAttackIpTagSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		ipAttackTags, total, err2 := wafLogService.GetAttackIpListApi(req)
		if err2 != nil {
			response.FailWithMessage("访问列表失败:"+err2.Error(), c)
		} else {
			response.OkWithDetailed(response.PageResult{
				List:      ipAttackTags,
				Total:     total,
				PageIndex: req.PageIndex,
				PageSize:  req.PageSize,
			}, "获取成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetAllIpTagApi 获取所有ip tag
func (w *WafLogAPi) GetAllIpTagApi(c *gin.Context) {

	// with_benign=1 用于批量删除弹窗：把被排除的标签也列出来，好清理历史数据
	withBenign := c.Query("with_benign") == "1" || c.Query("with_benign") == "true"
	ipAttackTags, err2 := wafLogService.GetAllAttackIPTagListApi(withBenign)
	if err2 != nil {
		response.FailWithMessage("访问ip tag 失败:"+err2.Error(), c)
	} else {
		response.OkWithDetailed(ipAttackTags, "获取成功", c)
	}
}

// DeleteTagByNameApi 删除指定标签
func (w *WafLogAPi) DeleteTagByNameApi(c *gin.Context) {
	var req request.WafAttackTagDeleteReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("参数解析失败: "+err.Error(), c)
		return
	}

	if global.GDATA_CURRENT_CHANGE {
		//如果正在切换库 跳过
		response.FailWithMessage("正在切换数据库请等待", c)
		return
	}

	// 验证标签名称
	if req.TagName == "" || req.TagName == "正常" {
		response.FailWithMessage("无效的标签名称", c)
		return
	}

	// 执行删除
	err2 := wafLogService.DeleteTagByNameApi(req.TagName, req.DeleteLogs)
	if err2 != nil {
		response.FailWithMessage("删除失败: "+err2.Error(), c)
	} else {
		if req.DeleteLogs {
			response.OkWithMessage("标签及相关日志删除成功", c)
		} else {
			response.OkWithMessage("标签统计数据删除成功", c)
		}
	}
}
func GenerateRawHTTPRequest(weblog innerbean.WebLog) string {

	reqUrl := weblog.URL
	if weblog.SrcURL != nil {
		reqUrl = string(weblog.SrcURL)
	}
	parsedURL, err := url.Parse(reqUrl)
	if err != nil {
		return ""
	}

	// 构建请求行
	pathWithQuery := parsedURL.Path
	if parsedURL.RawQuery != "" {
		pathWithQuery += "?" + parsedURL.RawQuery
	}

	// 根据协议确定 HTTP 版本
	httpVersion := "HTTP/1.1"
	if weblog.Scheme != "" {
		httpVersion = weblog.Scheme
	}

	// 处理敏感头信息
	maskedHeaders := maskSensitiveHeader(weblog.HEADER)
	headers := strings.Split(maskedHeaders, "\n")

	// 处理 Cookie
	maskedCookies := maskSensitiveCookies(weblog.COOKIES)
	if maskedCookies != "" {
		cookieHeader := fmt.Sprintf("Cookie: %s", maskedCookies)
		// 替换或添加 Cookie 头
		cookieFound := false
		for i, h := range headers {
			if strings.HasPrefix(strings.TrimSpace(h), "Cookie:") {
				headers[i] = cookieHeader
				cookieFound = true
				break
			}
		}
		if !cookieFound {
			headers = append(headers, cookieHeader)
		}
	}

	// 确保 Host 头存在
	host := parsedURL.Host
	if host != "" {
		hostExists := false
		for _, h := range headers {
			if strings.HasPrefix(strings.TrimSpace(strings.ToLower(h)), "host:") {
				hostExists = true
				break
			}
		}
		if !hostExists {
			headers = append(headers, fmt.Sprintf("Host: %s", host))
		}
	}

	// 构建最终 header
	var cleanHeaders []string
	for _, h := range headers {
		if trimmed := strings.TrimSpace(h); trimmed != "" {
			cleanHeaders = append(cleanHeaders, trimmed)
		}
	}

	// 构建完整请求
	requestLines := []string{
		fmt.Sprintf("%s %s %s",
			weblog.METHOD,
			pathWithQuery,
			httpVersion,
		),
	}
	requestLines = append(requestLines, cleanHeaders...)

	// 添加 body（如果有）
	if weblog.BODY != "" {
		requestLines = append(requestLines, "", weblog.BODY)
	}

	return strings.Join(requestLines, "\n")
}
func GenerateCurlRequest(weblog innerbean.WebLog) string {

	headers := strings.Split(weblog.HEADER, "\n")
	maskedHeaders := maskSensitiveHeader(weblog.HEADER)
	headers = strings.Split(maskedHeaders, "\n")
	headerStrings := ""
	for _, header := range headers {
		headerStrings += fmt.Sprintf("-H '%s' ", strings.TrimSpace(header))
	}

	maskedCookies := maskSensitiveCookies(weblog.COOKIES)

	reqUrl := weblog.URL
	if weblog.SrcURL != nil {
		reqUrl = string(weblog.SrcURL)
	}

	curlCommand := fmt.Sprintf(
		"curl -X %s %s \\\n	--url '%s' \\\n	--cookie '%s' \\\n	--data '%s'",
		weblog.METHOD,
		headerStrings,
		reqUrl,
		maskedCookies,
		weblog.BODY,
	)

	return curlCommand
}
func maskSensitiveHeader(header string) string {
	sensitiveKeys := []string{
		"Authorization", "Token", "Api-Key", "Secret", "Access-Token", "X-Api-Key",
		"X-Access-Token", "X-Secret", "Session-Key", "Set-Cookie",
	}
	maskedHeader := header
	for _, key := range sensitiveKeys {
		regex := regexp.MustCompile(fmt.Sprintf(`(?i)(%s):\s*[^\\n]+`, key))
		maskedHeader = regex.ReplaceAllString(maskedHeader, "$1: [MASKED]")
	}
	return maskedHeader
}

func maskSensitiveCookies(cookies string) string {
	cookieRegex := regexp.MustCompile(`(?i)(sessionid|auth|token|key|secret)=[^;]+`)
	return cookieRegex.ReplaceAllString(cookies, "$1=[MASKED]")
}
