package middleware

import (
	"SamWaf/common/zlog"
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

/*
*
全局异常插件：捕获下游 handler 的 panic，避免进程崩溃。

修复要点：
  - 原实现未调用 c.Next()，defer/recover 只包住本中间件自身（空）逻辑，下游 panic 根本不经过它，
    实际由 gin 默认 Recovery 兜底。此处补上 c.Next()，让 recover 真正覆盖后续 handler。
  - panic 详情（可能含内部路径、SQL、堆栈等敏感实现细节）仅记服务端日志；响应体只返回通用提示，
    避免信息泄露。
*/
func GinGlobalExceptionMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				// 完整错误与调用栈仅落日志，不回传客户端
				zlog.Error("全局异常捕获",
					"err", errorToString(r),
					"path", c.Request.URL.Path,
					"stack", string(debug.Stack()),
				)
				// 仅返回通用错误，避免把内部实现细节暴露给调用方
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"code": "500",
					"msg":  "服务器内部错误",
					"data": nil,
				})
			}
		}()
		c.Next()
	}
}

func errorToString(r interface{}) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	case string:
		return v
	default:
		// 兜底：panic 可能抛出任意类型（非 error/非 string），用 %v 安全格式化，
		// 避免原来 r.(string) 强制断言在此类情况下二次 panic。
		return fmt.Sprintf("%v", r)
	}
}
