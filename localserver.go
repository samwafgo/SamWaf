package main

import (
	"SamWaf/global"
	"SamWaf/router"
	"SamWaf/vue"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
)

func InitRouter(r *gin.Engine) {
	RouterGroup := r.Group("")
	router.ApiGroupApp.InitHostRouter(RouterGroup)
	router.ApiGroupApp.InitLogRouter(RouterGroup)
	router.ApiGroupApp.InitRuleRouter(RouterGroup)
	router.ApiGroupApp.InitEngineRouter(RouterGroup)
	router.ApiGroupApp.InitStatRouter(RouterGroup)

}
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
	if global.GWAF_RELEASE {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	r.Use(Cors()) //解决跨域

	if global.GWAF_RELEASE {
		index(r)
	}
	InitRouter(r)

	r.Run(":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT)) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	log.Println("本地 port:%d", global.GWAF_LOCAL_SERVER_PORT)
}

// vue静态路由
func index(r *gin.Engine) *gin.Engine {
	//静态文件路径
	const staticPath = `vue/dist/`
	var (
		js = assetfs.AssetFS{
			Asset:     vue.Asset,
			AssetDir:  vue.AssetDir,
			AssetInfo: nil,
			Prefix:    staticPath + "assets",
			Fallback:  "index.html",
		}
		fs = assetfs.AssetFS{
			Asset:     vue.Asset,
			AssetDir:  vue.AssetDir,
			AssetInfo: nil,
			Prefix:    staticPath,
			Fallback:  "index.html",
		}
	)
	// 加载静态文件
	r.StaticFS("/assets", &js)
	r.StaticFS("/favicon.ico", &fs)
	r.GET("/", func(c *gin.Context) {
		//设置响应状态
		c.Writer.WriteHeader(http.StatusOK)
		//载入首页
		indexHTML, _ := vue.Asset(staticPath + "index.html")
		c.Writer.Write(indexHTML)
		//响应HTML类型
		c.Writer.Header().Add("Accept", "text/html")
		//显示刷新
		c.Writer.Flush()
	})
	// 关键点【解决页面刷新404的问题】
	r.NoRoute(func(c *gin.Context) {
		//设置响应状态
		c.Writer.WriteHeader(http.StatusOK)
		//载入首页
		indexHTML, _ := vue.Asset(staticPath + "index.html")
		c.Writer.Write(indexHTML)
		//响应HTML类型
		c.Writer.Header().Add("Accept", "text/html")
		//显示刷新
		c.Writer.Flush()
	})
	return r
}
