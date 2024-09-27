package wafmangeweb

import (
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/router"
	"SamWaf/wafmangeweb/static"
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
	"time"
)

type WafWebManager struct {
	HttpServer *http.Server
	R          *gin.Engine
}

func (web *WafWebManager) initRouter(r *gin.Engine) {

	PublicRouterGroup := r.Group("")
	PublicRouterGroup.Use(middleware.SecApi())
	router.PublicApiGroupApp.InitLoginRouter(PublicRouterGroup)
	router.PublicApiGroupApp.InitCenterRouter(PublicRouterGroup) //注册中心接收接口

	RouterGroup := r.Group("")
	RouterGroup.Use(middleware.Auth(), middleware.CenterApi(), middleware.SecApi()) //TODO 中心管控 特定
	{
		router.ApiGroupApp.InitHostRouter(RouterGroup)
		router.ApiGroupApp.InitLogRouter(RouterGroup)
		router.ApiGroupApp.InitRuleRouter(RouterGroup)
		router.ApiGroupApp.InitEngineRouter(RouterGroup)
		router.ApiGroupApp.InitStatRouter(RouterGroup)
		router.ApiGroupApp.InitAllowIpRouter(RouterGroup)
		router.ApiGroupApp.InitAllowUrlRouter(RouterGroup)
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
		router.ApiGroupApp.InitWafCommonRouter(RouterGroup)
		router.ApiGroupApp.InitOneKeyModRouter(RouterGroup)
		router.ApiGroupApp.InitCenterRouter(RouterGroup)
		router.ApiGroupApp.InitLicenseRouter(RouterGroup)
		router.ApiGroupApp.InitSensitiveRouter(RouterGroup)
		router.ApiGroupApp.InitLoadBalanceRouter(RouterGroup)
	}
	r.Use(middleware.GinGlobalExceptionMiddleWare())
	if global.GWAF_RELEASE == "true" {
		static.Static(r, func(handlers ...gin.HandlerFunc) {
			r.NoRoute(handlers...)
		})
	}

}
func (web *WafWebManager) cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		if origin != "" {
			//TODO 将来要控制 蔡鹏 20221005
			// 将该域添加到allow-origin中
			c.Header("Access-Control-Allow-Origin", origin) //
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization,X-Token,Remote-Waf-User-Id,OPEN-X-Token")
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
func (web *WafWebManager) StartLocalServer() {
	if global.GWAF_RELEASE == "true" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()
	r.Use(web.cors()) //解决跨域

	web.initRouter(r)

	web.R = r
	web.HttpServer = &http.Server{
		Addr:    ":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT),
		Handler: r,
	}
	if err := web.HttpServer.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
		log.Printf("listen: %s\n", err)
	}

	log.Printf("本地 port:%d\n", global.GWAF_LOCAL_SERVER_PORT)
}

/*
*
关闭管理端web接口
*/
func (web *WafWebManager) CloseLocalServer() {
	log.Println("ready to close local server")
	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := web.HttpServer.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("local Server exiting")
}
