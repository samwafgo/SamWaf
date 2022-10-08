package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/waflog/request"
	"errors"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
	"log"
	"net/http"
	"strconv"
	"time"
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

	r.GET("/samwaf/resetWAF", func(c *gin.Context) {
		/*defer func() {
			c.JSON(http.StatusOK, response.Response{
				Code: -1,
				Data: "",
				Msg:  "重启指令失败",
			})
		}()*/
		//重启WAF引擎
		engineChan <- 1
		c.JSON(http.StatusOK, response.Response{
			Code: 200,
			Data: "",
			Msg:  "已发起重启指令",
		})
	})
	var waf_attack request.WafAttackLogSearch
	r.GET("/samwaf/waflog/attack/list", func(c *gin.Context) {
		err := c.ShouldBind(&waf_attack)
		if err == nil {

			var total int64 = 0
			var weblogs []innerbean.WebLog
			global.GWAF_LOCAL_DB.Debug().Limit(waf_attack.PageSize).Offset(waf_attack.PageSize * (waf_attack.PageIndex - 1)).Find(&weblogs)
			global.GWAF_LOCAL_DB.Debug().Model(&innerbean.WebLog{}).Count(&total)

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

	var waf_attack_detail_req request.WafAttackLogDetailReq
	r.GET("/samwaf/waflog/attack/detail", func(c *gin.Context) {
		err := c.ShouldBind(&waf_attack_detail_req)
		if err == nil {

			var weblog innerbean.WebLog
			global.GWAF_LOCAL_DB.Debug().Where("REQ_UUID=?", waf_attack_detail_req.REQ_UUID).Find(&weblog)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: weblog,
				Msg:  "获取成功",
			})
		}

	})

	var waf_host_req request.WafHostSearchReq
	r.GET("/samwaf/wafhost/host/list", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_req)
		if err == nil {

			var total int64 = 0
			var webhosts []model.Hosts
			global.GWAF_LOCAL_DB.Debug().Limit(waf_host_req.PageSize).Offset(waf_host_req.PageSize * (waf_host_req.PageIndex - 1)).Find(&webhosts)
			global.GWAF_LOCAL_DB.Debug().Model(&model.Hosts{}).Count(&total)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: response.PageResult{
					List:      webhosts,
					Total:     total,
					PageIndex: waf_attack.PageIndex,
					PageSize:  waf_attack.PageSize,
				},
				Msg: "获取成功",
			})
		}

	})
	var waf_host_detail_req request.WafHostDetailReq
	r.GET("/samwaf/wafhost/host/detail", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_detail_req)
		if err == nil {

			var webhost model.Hosts
			global.GWAF_LOCAL_DB.Debug().Where("CODE=?", waf_host_detail_req.CODE).Find(&webhost)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: webhost,
				Msg:  "获取成功",
			})
		}

	})

	var waf_host_add_req request.WafHostAddReq
	r.POST("/samwaf/wafhost/host/add", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_add_req)
		if err == nil {

			if (!errors.Is(global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", waf_host_add_req.Host, waf_host_add_req.Port).Error, gorm.ErrRecordNotFound)) {
				c.JSON(http.StatusOK, response.Response{
					Code: 404,
					Msg:  "当前网站和端口已经存在", //可以后续考虑再次加入已存在的host的返回，前台进行编辑
				})
				return
			}
			var waf_host = &model.Hosts{
				USER_CODE:     global.GWAF_USER_CODE,
				Tenant_id:     global.GWAF_TENANT_ID,
				Code:          uuid.NewV4().String(),
				Host:          waf_host_add_req.Host,
				Port:          waf_host_add_req.Port,
				Ssl:           waf_host_add_req.Ssl,
				GUARD_STATUS:  0,
				REMOTE_SYSTEM: waf_host_add_req.REMOTE_SYSTEM,
				REMOTE_APP:    waf_host_add_req.REMOTE_APP,
				Remote_host:   waf_host_add_req.Remote_host,
				Remote_port:   waf_host_add_req.Remote_port,
				Certfile:      waf_host_add_req.Certfile,
				Keyfile:       waf_host_add_req.Keyfile,
				REMARKS:       waf_host_add_req.REMARKS,
				CREATE_TIME:   time.Now(),
				UPDATE_TIME:   time.Now(),
			}
			//waf_host_add_req.USER_CODE =
			global.GWAF_LOCAL_DB.Debug().Create(waf_host)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: "",
				Msg:  "添加成功",
			})
		} else {
			log.Println("添加解析失败")
			c.JSON(http.StatusOK, response.Response{
				Code: -1,
				Data: err.Error(),
				Msg:  "添加失败",
			})
			return
		}

	})

	var waf_host_del_req request.WafHostDelReq
	r.GET("/samwaf/wafhost/host/del", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_del_req)
		if err == nil {

			var webhost model.Hosts
			err = global.GWAF_LOCAL_DB.Where("CODE = ?", waf_host_del_req.CODE).First(&webhost).Error
			if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusOK, response.Response{
					Code: -1,
					Data: err.Error(),
					Msg:  "请检测参数",
				})
				return
			}
			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: -1,
					Data: err.Error(),
					Msg:  "发生错误",
				})
				return
			}
			err = global.GWAF_LOCAL_DB.Where("CODE = ?", waf_host_del_req.CODE).Delete(model.Hosts{}).Error

			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: -1,
					Data: err.Error(),
					Msg:  "删除失败",
				})
				return
			}

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: "",
				Msg:  "删除成功",
			})
		}

	})

	var waf_host_edit_req request.WafHostEditReq
	r.POST("/samwaf/wafhost/host/edit", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_edit_req)
		if err == nil {

			var webhost model.Hosts
			global.GWAF_LOCAL_DB.Debug().Where("host = ? and port= ?", waf_host_edit_req.Host, waf_host_edit_req.Port).Find(&webhost)

			if webhost.Id != 0 && webhost.Code != waf_host_edit_req.CODE {
				c.JSON(http.StatusOK, response.Response{
					Code: 404,
					Msg:  "当前网站和端口已经存在", //可以后续考虑再次加入已存在的host的返回，前台进行编辑
				})
				return
			}
			hostMap := map[string]interface{}{
				"Host":          waf_host_edit_req.Host,
				"Port":          waf_host_edit_req.Port,
				"Ssl":           waf_host_edit_req.Ssl,
				"GUARD_STATUS":  0,
				"REMOTE_SYSTEM": waf_host_edit_req.REMOTE_SYSTEM,
				"REMOTE_APP":    waf_host_edit_req.REMOTE_APP,
				"Remote_host":   waf_host_edit_req.Remote_host,
				"Remote_port":   waf_host_edit_req.Remote_port,
				"REMARKS":       waf_host_edit_req.REMARKS,

				"Certfile":    waf_host_edit_req.Certfile,
				"Keyfile":     waf_host_edit_req.Keyfile,
				"UPDATE_TIME": time.Now(),
			}
			//var edit_waf_host model.Hosts
			//global.GWAF_LOCAL_DB.Debug().Where("CODE=?", waf_host_edit_req.CODE).Find(edit_waf_host)

			err = global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", waf_host_edit_req.CODE).Updates(hostMap).Error
			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: 200,
					Data: err.Error(),
					Msg:  "编辑失败",
				})
			} else {
				c.JSON(http.StatusOK, response.Response{
					Code: 200,
					Data: "",
					Msg:  "编辑成功",
				})
			}

		} else {
			log.Println("添加解析失败")
			c.JSON(http.StatusOK, response.Response{
				Code: -1,
				Data: err.Error(),
				Msg:  "编辑失败",
			})
			return
		}

	})
	r.Run(":" + strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT)) // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
	log.Println("本地 port:%d", global.GWAF_LOCAL_SERVER_PORT)
}
