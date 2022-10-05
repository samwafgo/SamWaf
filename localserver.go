package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
)

func StartLocalServer() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.GET("/list_log", func(c *gin.Context) {
		var weblogs []innerbean.WebLog
		global.GWAF_LOCAL_DB.Debug().Find(&weblogs)

		c.JSON(http.StatusOK, weblogs)
	})
	r.Run(":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT)) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	log.Println("本地 port:%d", global.GWAF_LOCAL_SERVER_PORT)
}
