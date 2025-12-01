package wafmangeweb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/router"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafmangeweb/static"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

type WafWebManager struct {
	HttpServer            *http.Server
	R                     *gin.Engine
	LogName               string
	restartWatcherStarted bool
	isShuttingDown        bool // 标记是否正在完全关闭（非重启）
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
		router.ApiGroupApp.InitIPFailureRouter(RouterGroup)
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
		router.ApiGroupApp.InitNotifyChannelRouter(RouterGroup)
		router.ApiGroupApp.InitNotifySubscriptionRouter(RouterGroup)
		router.ApiGroupApp.InitNotifyLogRouter(RouterGroup)
		router.ApiGroupApp.InitFirewallIPBlockRouter(RouterGroup)
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

	// 启动重启信号监听（只启动一次）
	if !web.restartWatcherStarted {
		web.restartWatcherStarted = true
		go web.WatchRestartSignal()
	}

	// 检查是否启用 SSL
	if global.GWAF_SSL_ENABLE {
		// 获取证书文件路径
		certPath := filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager", "domain.crt")
		keyPath := filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager", "domain.key")

		// 检查证书文件是否存在
		if _, err := os.Stat(certPath); err != nil {
			zlog.Warn(web.LogName, "SSL证书文件不存在，降级使用 HTTP: ", certPath)
			// 降级到 HTTP
			zlog.Info(web.LogName, "启动 HTTP 管理端（降级模式）, port:", global.GWAF_LOCAL_SERVER_PORT)
			if err := web.HttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
				zlog.Error(web.LogName, errMsg)
				return err
			}
			return nil
		}

		if _, err := os.Stat(keyPath); err != nil {
			zlog.Warn(web.LogName, "SSL私钥文件不存在，降级使用 HTTP: ", keyPath)
			// 降级到 HTTP
			zlog.Info(web.LogName, "启动 HTTP 管理端（降级模式）, port:", global.GWAF_LOCAL_SERVER_PORT)
			if err := web.HttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
				zlog.Error(web.LogName, errMsg)
				return err
			}
			return nil
		}

		// 尝试加载证书
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			zlog.Warn(web.LogName, "SSL证书加载失败，降级使用 HTTP: ", err.Error())
			// 降级到 HTTP
			zlog.Info(web.LogName, "启动 HTTP 管理端（降级模式）, port:", global.GWAF_LOCAL_SERVER_PORT)
			if err := web.HttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
				zlog.Error(web.LogName, errMsg)
				return err
			}
			return nil
		}

		// 使用混合监听器，同时支持 HTTPS 和 HTTP（降级方案）
		zlog.Info(web.LogName, "启动 HTTPS/HTTP 混合管理端, port:", global.GWAF_LOCAL_SERVER_PORT)
		if err := web.listenAndServeHybrid(cert); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
			zlog.Error(web.LogName, errMsg)
			return err
		}
	} else {
		// 使用 HTTP 启动服务
		zlog.Info(web.LogName, "启动 HTTP 管理端, port:", global.GWAF_LOCAL_SERVER_PORT)
		if err := web.HttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errMsg := fmt.Sprintf("启动管理界面失败: %s", err.Error())
			zlog.Error(web.LogName, errMsg)
			return err
		}
	}

	return nil
}

// listenAndServeHybrid 混合监听器，同时支持 HTTPS 和 HTTP
func (web *WafWebManager) listenAndServeHybrid(cert tls.Certificate) error {
	addr := web.HttpServer.Addr
	if addr == "" {
		addr = ":http"
	}

	// 创建基础监听器
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	// 创建混合监听器
	hybridListener := &hybridListener{
		Listener: ln,
		cert:     cert,
	}

	// 使用混合监听器启动服务
	return web.HttpServer.Serve(hybridListener)
}

// hybridListener 混合监听器，可以同时处理 HTTPS 和 HTTP 连接
type hybridListener struct {
	net.Listener
	cert tls.Certificate
}

func (l *hybridListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// 返回混合连接，用于判断是 HTTPS 还是 HTTP
	return &hybridConn{
		Conn: conn,
		cert: l.cert,
	}, nil
}

// hybridConn 混合连接，可以自动识别 HTTPS 和 HTTP
type hybridConn struct {
	net.Conn
	cert      tls.Certificate
	tlsConn   *tls.Conn
	firstRead bool
	isTLS     bool
}

func (c *hybridConn) Read(b []byte) (n int, err error) {
	// 第一次读取时判断是 TLS 还是普通 HTTP
	if !c.firstRead {
		c.firstRead = true

		// 读取第一个字节来判断协议
		firstByte := make([]byte, 1)
		n, err := c.Conn.Read(firstByte)
		if err != nil {
			return 0, err
		}

		// TLS 握手的第一个字节是 0x16 (22)，表示 Handshake
		if n > 0 && firstByte[0] == 0x16 {
			// 这是 TLS 连接
			c.isTLS = true

			// 创建 TLS 配置
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{c.cert},
				MinVersion:   tls.VersionTLS12,
			}

			// 创建 TLS 连接包装器
			// 将第一个字节放回，让 TLS 握手可以正常进行
			wrappedConn := &firstByteConn{
				Conn:      c.Conn,
				firstByte: firstByte[0],
				firstRead: false,
			}

			c.tlsConn = tls.Server(wrappedConn, tlsConfig)

			// 执行 TLS 握手
			if err := c.tlsConn.Handshake(); err != nil {
				zlog.Warn("WafWebManager", "TLS握手失败，尝试降级到HTTP: ", err.Error())
				// TLS 握手失败，关闭连接
				c.Conn.Close()
				return 0, err
			}

			// 使用 TLS 连接读取数据
			return c.tlsConn.Read(b)
		} else {
			// 这是普通 HTTP 连接
			c.isTLS = false
			zlog.Debug("WafWebManager", "检测到HTTP连接，使用降级模式")

			// 将第一个字节放到缓冲区
			if n > 0 {
				b[0] = firstByte[0]
				// 继续读取剩余数据
				if len(b) > 1 {
					n2, err2 := c.Conn.Read(b[1:])
					return n + n2, err2
				}
				return 1, nil
			}
		}
	}

	// 后续读取
	if c.isTLS && c.tlsConn != nil {
		return c.tlsConn.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *hybridConn) Write(b []byte) (n int, err error) {
	if c.isTLS && c.tlsConn != nil {
		return c.tlsConn.Write(b)
	}
	return c.Conn.Write(b)
}

func (c *hybridConn) Close() error {
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
	return c.Conn.Close()
}

// firstByteConn 用于将第一个字节放回连接
type firstByteConn struct {
	net.Conn
	firstByte byte
	firstRead bool
}

func (c *firstByteConn) Read(b []byte) (n int, err error) {
	if !c.firstRead {
		c.firstRead = true
		if len(b) > 0 {
			b[0] = c.firstByte
			if len(b) > 1 {
				n2, err2 := c.Conn.Read(b[1:])
				return 1 + n2, err2
			}
			return 1, nil
		}
	}
	return c.Conn.Read(b)
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

// WatchRestartSignal 监听重启信号
func (web *WafWebManager) WatchRestartSignal() {
	go func() {
		// 使用 ticker 定期检查关闭信号
		shutdownCheckTicker := time.NewTicker(500 * time.Millisecond)
		defer shutdownCheckTicker.Stop()

		for {
			select {
			case <-global.GWAF_CHAN_MANAGER_RESTART:
				// 检查是否正在完全关闭系统
				if global.GWAF_SHUTDOWN_SIGNAL || web.isShuttingDown {
					zlog.Warn(web.LogName, "System is shutting down, ignoring restart request")
					continue
				}

				zlog.Info(web.LogName, "Received manager restart signal, starting restart...")

				// 关闭当前服务器
				web.CloseLocalServer()

				// 等待服务完全关闭
				time.Sleep(2 * time.Second)

				// 再次检查是否收到关闭信号
				if global.GWAF_SHUTDOWN_SIGNAL || web.isShuttingDown {
					zlog.Warn(web.LogName, "System is shutting down, canceling restart")
					return
				}

				// SSL配置已经通过API更新到全局变量，直接使用即可
				zlog.Info(web.LogName, "Current SSL configuration status: ", global.GWAF_SSL_ENABLE)

				// 重新启动服务器
				zlog.Info(web.LogName, "Restarting manager...")
				go func() {
					if err := web.StartLocalServer(); err != nil {
						zlog.Error(web.LogName, "Failed to restart manager: ", err.Error())
					}
				}()

				zlog.Info(web.LogName, "Manager restart completed")

			case <-shutdownCheckTicker.C:
				// 定期检查系统关闭信号，如果系统正在关闭则退出goroutine
				if global.GWAF_SHUTDOWN_SIGNAL || web.isShuttingDown {
					zlog.Info(web.LogName, "Detected system shutdown signal, exiting restart watcher")
					return
				}
			}
		}
	}()
}

// Shutdown 完全关闭管理端
func (web *WafWebManager) Shutdown() {
	web.isShuttingDown = true
	web.CloseLocalServer()
}
