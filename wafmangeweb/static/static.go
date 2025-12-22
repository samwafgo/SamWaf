package static

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/public"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

var static fs.FS

func initStatic() {
	static = public.Public
}

// correctMimeTypeMiddleware 修正静态文件的 MIME 类型
// 解决某些 Windows 系统注册表中 .js 被错误配置为 application/x-js 的问题
func correctMimeTypeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		ext := strings.ToLower(filepath.Ext(path))

		// 确保 JavaScript 文件使用正确的 MIME 类型
		// 避免某些系统返回 application/x-js 导致 ES Module 加载失败
		switch ext {
		case ".js", ".mjs":
			c.Header("Content-Type", "text/javascript; charset=utf-8")
		case ".css":
			c.Header("Content-Type", "text/css; charset=utf-8")
		case ".json":
			c.Header("Content-Type", "application/json; charset=utf-8")
		case ".wasm":
			c.Header("Content-Type", "application/wasm")
		}

		c.Next()
	}
}
func initIndex() {
	indexFile, err := static.Open("index.html")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			zlog.Error("index.html not exist, you may forget to put dist of frontend to public/dist")
		}
		zlog.Error("failed to read index.html: %v", err)
	}
	defer func() {
		if indexFile != nil {
			_ = indexFile.Close()
		} else {
			zlog.Error("index.html not exist, you may forget to put dist of frontend to public/dist .Download from https://github.com/samwafgo/SamWafWeb/releases")
		}
	}()
	index, err := io.ReadAll(indexFile)
	if err != nil {
		zlog.Error("failed to read dist/index.html")
	}
	global.GWAF_LOCAL_INDEX_HTML = string(index)
}
func Static(r *gin.Engine, noRoute func(handlers ...gin.HandlerFunc)) {
	initStatic()
	initIndex()

	// 应用 MIME 类型修正中间件
	r.Use(correctMimeTypeMiddleware())

	folders := []string{"assets"}
	for i, folder := range folders {
		sub, err := fs.Sub(static, folder)
		if err != nil {
			zlog.Error("can't find folder: %s", folder)
		}
		r.StaticFS(fmt.Sprintf("/%s", folders[i]), http.FS(sub))
	}
	r.GET("/favicon.ico", func(c *gin.Context) {
		faviconFile, err := static.Open("favicon.ico")
		if err != nil {
			zlog.Error("can't find favicon.ico")
			c.Status(http.StatusNotFound)
			return
		}
		defer faviconFile.Close()

		c.Header("Content-Type", "image/x-icon")
		c.Status(http.StatusOK)
		_, _ = io.Copy(c.Writer, faviconFile)
	})
	r.GET("/robots.txt", func(c *gin.Context) {
		robotFile, err := static.Open("robots.txt")
		if err != nil {
			zlog.Error("can't find robots.txt")
			c.Status(http.StatusNotFound)
			return
		}
		defer robotFile.Close()

		c.Header("Content-Type", "text/plain")
		c.Status(http.StatusOK)
		_, _ = io.Copy(c.Writer, robotFile)
	})

	noRoute(func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.Status(200)
		_, _ = c.Writer.WriteString(global.GWAF_LOCAL_INDEX_HTML)
		c.Writer.Flush()
		c.Writer.WriteHeaderNow()
	})
}
