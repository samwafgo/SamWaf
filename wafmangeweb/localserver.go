package wafmangeweb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/router"
	"SamWaf/service/waf_service"
	"SamWaf/wafmangeweb/static"
	"context"
	"errors"
	"fmt"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

type WafWebManager struct {
	HttpServer *http.Server
	R          *gin.Engine
	LogName    string
}

func (web *WafWebManager) initRouter(r *gin.Engine) {

	PublicRouterGroup := r.Group("")
	PublicRouterGroup.Use(middleware.SecApi(), middleware.IPWhitelist())
	router.PublicApiGroupApp.InitLoginRouter(PublicRouterGroup)
	router.PublicApiGroupApp.InitCenterRouter(PublicRouterGroup) //注册中心接收接口

	RouterGroup := r.Group("")
	RouterGroup.Use(middleware.Auth(), middleware.CenterApi(), middleware.SecApi(), middleware.GinGlobalExceptionMiddleWare(), middleware.IPWhitelist()) //TODO 中心管控 特定
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
		router.ApiGroupApp.InitSslConfigRouter(RouterGroup)
		router.ApiGroupApp.InitBatchTaskRouter(RouterGroup)
		router.ApiGroupApp.InitSslOrderRouter(RouterGroup)
		router.ApiGroupApp.InitWafSslExpireRouter(RouterGroup)
		router.ApiGroupApp.InitWafHttpAuthBaseRouter(RouterGroup)
		router.ApiGroupApp.InitWafTaskRouter(RouterGroup)
		router.ApiGroupApp.InitWafBlockingPageRouter(RouterGroup)
		router.ApiGroupApp.InitGPTRouter(RouterGroup)
		router.ApiGroupApp.InitWafOtpRouter(RouterGroup)
		router.ApiGroupApp.InitAnalysisRouter(RouterGroup)
		router.ApiGroupApp.InitWafPrivateInfoRouter(RouterGroup)
		router.ApiGroupApp.InitWafPrivateGroupRouter(RouterGroup)
		router.ApiGroupApp.InitWafCacheRuleRouter(RouterGroup)
		router.ApiGroupApp.InitWafTunnelRouter(RouterGroup)
		router.ApiGroupApp.InitWafVpConfigRouter(RouterGroup)
		router.ApiGroupApp.InitWafFileRouter(RouterGroup)
		router.ApiGroupApp.InitWafSystemMonitorRouter(RouterGroup)
		router.ApiGroupApp.InitWafCaServerInfoRouter(RouterGroup)
		router.ApiGroupApp.InitSqlQueryRouter(RouterGroup)
	}

	if global.GWAF_RELEASE == "true" {
		static.Static(r, func(handlers ...gin.HandlerFunc) {
			r.NoRoute(handlers...)
		})
		zlog.Info(web.LogName, "use static asset")
	} else {
		zlog.Info(web.LogName, "no use static asset")
	}

	//性能检测部分
	if global.GCONFIG_RECORD_DEBUG_ENABLE == 1 {
		zlog.Info(web.LogName, "Debug On")
		debugGroup := r.Group("/debug", func(c *gin.Context) {
			if global.GCONFIG_RECORD_DEBUG_ENABLE == 0 {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			if global.GCONFIG_RECORD_DEBUG_PWD != "" {
				if c.Request.Header.Get("Authorization") != global.GCONFIG_RECORD_DEBUG_PWD {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}
			c.Next()
		})
		pprof.RouteRegister(debugGroup, "pprof")
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
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization,X-Token,Remote-Waf-User-Id,OPEN-X-Token,X-Login-Type,X-Mobile-Token")
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

// StartLocalServer 启动本地管理服务器
func (web *WafWebManager) StartLocalServer() error {
	if global.GWAF_RELEASE == "true" {
		gin.SetMode(gin.ReleaseMode)
		gin.DefaultWriter = io.Discard
	}
	if global.GWAF_IP_WHITELIST == "0.0.0.0/0,::/0" {
		zlog.Warn("管理端未配置 IP 白名单，默认允许所有 IP4（0.0.0.0/0） IPv6 ::/0 访问")
	}
	r := gin.Default()
	r.Use(web.cors()) //解决跨域
	web.initRouter(r)

	web.R = r
	web.HttpServer = &http.Server{
		Addr:    ":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT),
		Handler: r,
	}
	err := waf_service.WafTokenInfoServiceApp.ReloadAllValidTokensToCache()
	if err != nil {
		zlog.Info("加载token到cache错误", err.Error())
	}
	// 正式启动服务
	if err := web.HttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
		zlog.Error(web.LogName, errMsg)
		return err
	}

	zlog.Info(web.LogName, "本地 port:", global.GWAF_LOCAL_SERVER_PORT)
	return nil
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

	defer func() {
		defer cancel()
	}()

	if web != nil && web.HttpServer != nil {
		if err := web.HttpServer.Shutdown(ctx); err != nil {
			zlog.Error(web.LogName, "Server forced to shutdown:", err.Error())
		}
		zlog.Info(web.LogName, "local Server exiting")
	} else {
		zlog.Info("local Server exiting")
	}

}
