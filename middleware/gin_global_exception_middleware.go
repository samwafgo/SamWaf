package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

/*
*
全局异常插件
*/
func GinGlobalExceptionMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				//如果后续没动作，c.AbortWithStatusJSON其实也可以，省去了return。
				c.JSON(http.StatusInternalServerError, gin.H{
					"code": "500",
					"msg":  errorToString(r),
					"data": nil,
				})
				return
			}
		}()
	}
}
func errorToString(r interface{}) string {
	switch v := r.(type) {
	case error:
		return v.Error()
	default:
		return r.(string)
	}
}
