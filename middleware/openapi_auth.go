package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// rateLimitEntry 限流计数器条目
type rateLimitEntry struct {
	count     int64
	windowEnd time.Time
	mu        sync.Mutex
}

var (
	openApiKeyService = waf_service.WafOPlatformKeyServiceApp
	openApiLogService = waf_service.WafOPlatformLogServiceApp
	rateLimitMap      sync.Map // key: api_key_id, value: *rateLimitEntry
)

// bodyWriter 包装 gin.ResponseWriter，用于捕获响应体
type bodyWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func newBodyWriter(c *gin.Context) *bodyWriter {
	return &bodyWriter{
		ResponseWriter: c.Writer,
		body:           &bytes.Buffer{},
		statusCode:     200,
	}
}

func (w *bodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *bodyWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// ValidateOpenApiKey 校验 API Key 并设置上下文标记，返回 Key 记录和是否通过
func ValidateOpenApiKey(c *gin.Context, apiKey string) (model.OPlatformKey, bool) {
	// 1. 检查开放平台总开关
	if global.GCONFIG_OPEN_PLATFORM_ENABLED == 0 {
		response.AuthFailWithMessage("开放平台已关闭", c)
		return model.OPlatformKey{}, false
	}

	// 2. 查询 Key 记录
	keyBean, err := openApiKeyService.GetByApiKey(apiKey)
	if err != nil {
		response.AuthFailWithMessage("无效的 API Key", c)
		return model.OPlatformKey{}, false
	}

	// 3. 检查启用状态
	if keyBean.Status != 1 {
		response.AuthFailWithMessage("API Key 已禁用", c)
		return model.OPlatformKey{}, false
	}

	// 4. 检查过期时间
	if keyBean.ExpireTime != "" {
		expireTime, parseErr := time.Parse("2006-01-02 15:04:05", keyBean.ExpireTime)
		if parseErr == nil && time.Now().After(expireTime) {
			response.AuthFailWithMessage("API Key 已过期", c)
			return model.OPlatformKey{}, false
		}
	}

	// 5. 检查 IP 白名单
	if keyBean.IPWhitelist != "" {
		clientIP := c.ClientIP()
		allowedIPs := strings.Split(keyBean.IPWhitelist, ",")
		ipAllowed := false
		for _, allowedIP := range allowedIPs {
			allowedIP = strings.TrimSpace(allowedIP)
			if allowedIP == "" {
				continue
			}
			// 支持 CIDR 格式
			if strings.Contains(allowedIP, "/") {
				_, ipNet, cidrErr := net.ParseCIDR(allowedIP)
				if cidrErr == nil && ipNet.Contains(net.ParseIP(clientIP)) {
					ipAllowed = true
					break
				}
			} else if allowedIP == clientIP {
				ipAllowed = true
				break
			}
		}
		if !ipAllowed {
			response.AuthFailWithMessage("IP 不在白名单中", c)
			return model.OPlatformKey{}, false
		}
	}

	// 6. 限流检查（按分钟）
	if keyBean.RateLimit > 0 {
		entryVal, _ := rateLimitMap.LoadOrStore(keyBean.Id, &rateLimitEntry{
			windowEnd: time.Now().Add(time.Minute),
		})
		entry := entryVal.(*rateLimitEntry)
		entry.mu.Lock()
		now := time.Now()
		if now.After(entry.windowEnd) {
			// 新的时间窗口
			entry.count = 0
			entry.windowEnd = now.Add(time.Minute)
		}
		entry.count++
		currentCount := entry.count
		entry.mu.Unlock()

		if currentCount > keyBean.RateLimit {
			response.FailWithMessage("请求频率超限，请稍后再试", c)
			return model.OPlatformKey{}, false
		}
	}

	// 7. 设置 OpenAPI 标记（用于 response 跳过 AES 加密）
	c.Set("is_openapi", true)
	c.Set("openapi_key_id", keyBean.Id)
	c.Set("openapi_key_name", keyBean.KeyName)

	return keyBean, true
}

// OpenApiLogMiddleware 记录 OpenAPI 调用日志的中间件
// 在 Auth 之后调用，负责捕获请求/响应并异步写日志
func OpenApiLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isOpenApi, exists := c.Get("is_openapi")
		if !exists || isOpenApi != true {
			c.Next()
			return
		}

		startTime := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		clientIP := c.ClientIP()

		keyId, _ := c.Get("openapi_key_id")
		keyName, _ := c.Get("openapi_key_name")

		// 读取请求体（文件类请求不记录 body）
		requestBody := ""
		contentType := c.GetHeader("Content-Type")
		isFileRequest := strings.Contains(contentType, "multipart") ||
			strings.Contains(path, "/download") ||
			strings.Contains(path, "/upload")

		if !isFileRequest && c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, 2048))
			if err == nil {
				requestBody = string(bodyBytes)
				// 恢复 body 供后续 handler 使用
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// 包装 ResponseWriter 以捕获响应
		bw := newBodyWriter(c)
		c.Writer = bw

		c.Next()

		duration := time.Since(startTime).Milliseconds()

		// 响应体（截断超过 2KB 的部分）
		responseBody := ""
		if !isFileRequest {
			responseBody = bw.body.String()
			if len(responseBody) > 2048 {
				responseBody = responseBody[:2048] + "...(truncated)"
			}
		}

		// 异步记录日志
		logEntry := model.OPlatformLog{
			ApiKeyId:      keyId.(string),
			KeyName:       keyName.(string),
			RequestPath:   path,
			RequestMethod: method,
			RequestBody:   requestBody,
			ResponseBody:  responseBody,
			ClientIP:      clientIP,
			StatusCode:    bw.statusCode,
			Duration:      duration,
			TimeStr:       startTime.Format("2006-01-02 15:04:05"),
		}
		openApiLogService.AddLogAsync(logEntry)

		// 异步更新调用次数
		go func() {
			if id, ok := keyId.(string); ok && id != "" {
				openApiKeyService.IncrCallCount(id)
			}
		}()

		zlog.Debug("OpenAPI调用", "path", path, "method", method, "ip", clientIP, "duration_ms", duration)
	}
}
