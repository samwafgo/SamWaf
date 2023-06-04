package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/router"
	"SamWaf/vue"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gin-gonic/gin"
	"log"
	"net"
	"net/http"
	"strconv"
)

func InitRouter(r *gin.Engine) {
	RouterGroup := r.Group("")
	RouterGroup.Use(middleware.Auth())
	{
		router.ApiGroupApp.InitHostRouter(RouterGroup)
		router.ApiGroupApp.InitLogRouter(RouterGroup)
		router.ApiGroupApp.InitRuleRouter(RouterGroup)
		router.ApiGroupApp.InitEngineRouter(RouterGroup)
		router.ApiGroupApp.InitStatRouter(RouterGroup)
		router.ApiGroupApp.InitWhiteIpRouter(RouterGroup)
		router.ApiGroupApp.InitWhiteUrlRouter(RouterGroup)
		router.ApiGroupApp.InitLdpUrlRouter(RouterGroup)
		router.ApiGroupApp.InitAntiCCRouter(RouterGroup)
		router.ApiGroupApp.InitBlockIpRouter(RouterGroup)
		router.ApiGroupApp.InitBlockUrlRouter(RouterGroup)
		router.ApiGroupApp.InitAccountRouter(RouterGroup)
		router.ApiGroupApp.InitAccountLogRouter(RouterGroup)
		router.ApiGroupApp.InitLoginOutRouter(RouterGroup)
		router.ApiGroupApp.InitSysLogRouter(RouterGroup)
		router.ApiGroupApp.InitWebSocketRouter(RouterGroup)
		router.ApiGroupApp.InitSysInfoRouter(RouterGroup)
		router.ApiGroupApp.InitSystemConfigRouter(RouterGroup)
	}
	PublicRouterGroup := r.Group("")
	router.PublicApiGroupApp.InitLoginRouter(PublicRouterGroup)

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
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization,X-Token")
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
	if global.GWAF_RELEASE == "true" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	r.Use(Cors()) //解决跨域

	if global.GWAF_RELEASE == "true" {
		index(r)
	}
	InitRouter(r)

	l, err := net.Listen("tcp4", ":"+strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT))
	if err != nil {
		log.Fatal(err)
	}
	r.RunListener(l)
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
