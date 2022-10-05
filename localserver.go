package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/waflog/request"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
)

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		if origin != "" {
			//TODO 将来要控制 蔡鹏 20221005
			// 将该域添加到allow-origin中
			c.Header("Access-Control-Allow-Origin", origin) //
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			//允许客户端传递校验信息比如 cookie
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		c.Next()
	}
}
func StartLocalServer() {
	r := gin.Default()
	r.Use(Cors()) //解决跨域

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	var waf_attack request.WafAttackLogSearch
	r.GET("/samwaf/waflog/attack/list", func(c *gin.Context) {
		err := c.ShouldBind(&waf_attack)
		if err == nil {

			var total int64 = 0
			var weblogs []innerbean.WebLog
			global.GWAF_LOCAL_DB.Debug().Limit(waf_attack.PageSize).Offset(waf_attack.PageSize * (waf_attack.PageIndex - 1)).Find(&weblogs)
			global.GWAF_LOCAL_DB.Debug().Count(&total)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: response.PageResult{
					List:      weblogs,
					Total:     total,
					PageIndex: waf_attack.PageIndex,
					PageSize:  waf_attack.PageSize,
				},
				Msg: "获取成功",
			})
		}

	})
	r.Run(":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT)) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	log.Println("本地 port:%d", global.GWAF_LOCAL_SERVER_PORT)
}
