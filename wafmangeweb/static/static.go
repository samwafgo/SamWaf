package static

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/public"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"io/fs"
	"net/http"
)

var static fs.FS

func initStatic() {
	static = public.Public
	return
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
		_ = indexFile.Close()
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
