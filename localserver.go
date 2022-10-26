package main

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"SamWaf/vue"
	"errors"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(Cors()) //解决跨域

	index(r)
	ruleHelper := &utils.RuleHelper{}
	r.GET("/samwaf/resetWAF", func(c *gin.Context) {
		/*defer func() {
			c.JSON(http.StatusOK, response.Response{
				HostCode: -1,
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
	r.GET("/samwaf/wafstat", func(c *gin.Context) {

		c.JSON(http.StatusOK, response.Response{
			Code: 200,
			Data: response2.WafStat{
				AttackCountOfToday:          0,
				VisitCountOfToday:           0,
				AttackCountOfYesterday:      0,
				VisitCountOfYesterday:       0,
				AttackCountOfLastWeekToday:  0,
				VisitCountOfLastWeekToday:   0,
				NormalIpCountOfToday:        0,
				IllegalIpCountOfToday:       0,
				NormalCountryCountOfToday:   0,
				IllegalCountryCountOfToday:  0,
				NormalProvinceCountOfToday:  0,
				IllegalProvinceCountOfToday: 0,
				NormalCityCountOfToday:      0,
				IllegalCityCountOfToday:     0,
			},
			Msg: "统计信息",
		})
	})
	var waf_attack request.WafAttackLogSearch
	r.GET("/samwaf/waflog/attack/list", func(c *gin.Context) {
		err := c.ShouldBind(&waf_attack)
		if err == nil {

			var total int64 = 0
			var weblogs []innerbean.WebLog
			global.GWAF_LOCAL_DB.Debug().Limit(waf_attack.PageSize).Offset(waf_attack.PageSize * (waf_attack.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
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
			zlog.Debug("添加解析失败")
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
			zlog.Debug("添加解析失败")
			c.JSON(http.StatusOK, response.Response{
				Code: -1,
				Data: err.Error(),
				Msg:  "编辑失败",
			})
			return
		}

	})

	var waf_host_guard_status_req request.WafHostGuardStatusReq
	r.GET("/samwaf/wafhost/host/guardstatus", func(c *gin.Context) {
		err := c.ShouldBind(&waf_host_guard_status_req)
		if err == nil {

			hostMap := map[string]interface{}{
				"GUARD_STATUS": waf_host_guard_status_req.GUARD_STATUS,
				"UPDATE_TIME":  time.Now(),
			}

			err = global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", waf_host_guard_status_req.CODE).Updates(hostMap).Error
			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: 200,
					Data: err.Error(),
					Msg:  "状态失败",
				})
			} else {
				var webHost model.Hosts
				err = global.GWAF_LOCAL_DB.Where("CODE = ?", waf_host_guard_status_req.CODE).First(&webHost).Error
				//发送状态改变通知
				hostChan <- webHost
				c.JSON(http.StatusOK, response.Response{
					Code: 200,
					Data: "",
					Msg:  "状态成功",
				})
			}

		} else {
			zlog.Debug("状态解析失败")
			c.JSON(http.StatusOK, response.Response{
				Code: -1,
				Data: err.Error(),
				Msg:  "状态失败",
			})
			return
		}

	})

	var waf_rule_detail_req request.WafRuleDetailReq
	r.GET("/samwaf/wafhost/rule/detail", func(c *gin.Context) {
		err := c.ShouldBind(&waf_rule_detail_req)
		if err == nil {

			var rules model.Rules
			global.GWAF_LOCAL_DB.Debug().Where("RULE_CODE=?", waf_rule_detail_req.CODE).Find(&rules)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: rules,
				Msg:  "获取成功",
			})
		}

	})
	var waf_rule_search_req request.WafRuleSearchReq
	r.GET("/samwaf/wafhost/rule/list", func(c *gin.Context) {
		err := c.ShouldBind(&waf_rule_search_req)
		if err == nil {

			var total int64 = 0
			var rules []model.Rules
			global.GWAF_LOCAL_DB.Debug().Where("user_code=? and rule_status= 1", global.GWAF_USER_CODE).Limit(waf_rule_search_req.PageSize).Offset(waf_rule_search_req.PageSize * (waf_rule_search_req.PageIndex - 1)).Find(&rules)
			global.GWAF_LOCAL_DB.Debug().Model(&model.Rules{}).Count(&total)

			c.JSON(http.StatusOK, response.Response{
				Code: 200,
				Data: response.PageResult{
					List:      rules,
					Total:     total,
					PageIndex: waf_attack.PageIndex,
					PageSize:  waf_attack.PageSize,
				},
				Msg: "获取成功",
			})
		}

	})

	var waf_rule_add_req request.WafRuleAddReq
	r.POST("/samwaf/wafhost/rule/add", func(c *gin.Context) {
		err := c.ShouldBind(&waf_rule_add_req)
		if err == nil {

			var rule_tool = model.RuleTool{}
			rule_info, err := rule_tool.LoadRule(waf_rule_add_req.RuleJson)
			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: -1,
					Msg:  "解析错误",
				})
				return
			}

			var rulename = rule_info.RuleBase.RuleName //中文名
			if (!errors.Is(global.GWAF_LOCAL_DB.First(&model.Rules{}, "rule_name = ? and rule_code = ?", rulename, rule_info.RuleBase.RuleDomainCode).Error, gorm.ErrRecordNotFound)) {
				c.JSON(http.StatusOK, response.Response{
					Code: 404,
					Msg:  "当前规则名称已存在", //可以后续考虑再次加入已存在的返回，前台进行编辑
				})
				return
			}

			var rule_code = uuid.NewV4().String()
			rule_info.RuleBase.RuleName = strings.Replace(rule_code, "-", "", -1)

			var ruleContent = rule_tool.GenRuleInfo(rule_info, rulename)
			if waf_rule_add_req.IsManualRule == 1 {
				ruleContent = rule_info.RuleContent
				//检查规则是否合法
				err = ruleHelper.CheckRuleAvailable(ruleContent)
				if err != nil {
					c.JSON(http.StatusOK, response.Response{
						Code: -1,
						Data: err.Error(),
						Msg:  "规则校验失败",
					})
					return
				}
			}

			var waf_rule = &model.Rules{
				TenantId:        global.GWAF_TENANT_ID,
				HostCode:        rule_info.RuleBase.RuleDomainCode, //网站CODE
				RuleCode:        rule_code,
				RuleName:        rulename,
				RuleContent:     ruleContent,
				RuleContentJSON: waf_rule_add_req.RuleJson, //TODO 后续考虑是否应该再从结构转一次
				RuleVersionName: "初版",
				RuleVersion:     1,
				UserCode:        global.GWAF_USER_CODE,
				IsPublicRule:    0,
				IsManualRule:    waf_rule_add_req.IsManualRule,
				RuleStatus:      1,
			}
			//waf_host_add_req.USER_CODE =
			global.GWAF_LOCAL_DB.Debug().Create(waf_rule)

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

	var waf_rule_edit_req request.WafRuleEditReq
	r.POST("/samwaf/wafhost/rule/edit", func(c *gin.Context) {
		err := c.ShouldBind(&waf_rule_edit_req)
		if err == nil {

			var ruleTool = model.RuleTool{}
			ruleInfo, err := ruleTool.LoadRule(waf_rule_edit_req.RuleJson)
			if err != nil {
				c.JSON(http.StatusOK, response.Response{
					Code: -1,
					Msg:  "解析错误",
				})
				return
			}
			var ruleName = ruleInfo.RuleBase.RuleName //中文名

			var rule model.Rules
			global.GWAF_LOCAL_DB.Debug().Where("rule_name = ? and host_code= ?",
				ruleName, ruleInfo.RuleBase.RuleDomainCode).Find(&rule)

			if rule.Id != 0 && rule.RuleCode != waf_rule_edit_req.CODE {
				c.JSON(http.StatusOK, response.Response{
					Code: 404,
					Msg:  "当前规则名称已经存在", //可以后续考虑再次加入已存在的返回，前台进行编辑
				})
				return
			}

			global.GWAF_LOCAL_DB.Debug().Where("rule_code=?", waf_rule_edit_req.CODE).Find(&rule)

			ruleInfo.RuleBase.RuleName = strings.Replace(rule.RuleCode, "-", "", -1)
			var ruleContent = ruleTool.GenRuleInfo(ruleInfo, ruleName)
			if waf_rule_edit_req.IsManualRule == 1 {
				ruleContent = ruleInfo.RuleContent
				//检查规则是否合法
				err = ruleHelper.CheckRuleAvailable(ruleContent)
				if err != nil {
					c.JSON(http.StatusOK, response.Response{
						Code: -1,
						Data: err.Error(),
						Msg:  "规则校验失败",
					})
					return
				}
			}
			ruleMap := map[string]interface{}{
				"HostCode":        ruleInfo.RuleBase.RuleDomainCode, //TODO 注意字典名称
				"RuleName":        ruleName,
				"RuleContent":     ruleContent,
				"RuleContentJSON": waf_rule_edit_req.RuleJson, //TODO 后续考虑是否应该再从结构转一次
				"RuleVersionName": "初版",
				"RuleVersion":     rule.RuleVersion + 1,
				"User_code":       global.GWAF_USER_CODE,
				"IsPublicRule":    0,
				"IsManualRule":    waf_rule_edit_req.IsManualRule,
				"RuleStatus":      "1",
				//"UPDATE_TIME": time.Now(),
			}
			err = global.GWAF_LOCAL_DB.Debug().Model(model.Rules{}).Where("rule_code=?", waf_rule_edit_req.CODE).Updates(ruleMap).Error
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

	var waf_rule_del_req request.WafRuleDelReq
	r.GET("/samwaf/wafhost/rule/del", func(c *gin.Context) {
		err := c.ShouldBind(&waf_rule_del_req)
		if err == nil {

			var rule model.Rules
			err = global.GWAF_LOCAL_DB.Where("rule_code = ?", waf_rule_del_req.CODE).First(&rule).Error
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
			rule_map := map[string]interface{}{
				"RuleStatus":  "999",
				"RuleVersion": 999999,
			}
			err = global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code = ?", waf_rule_del_req.CODE).Updates(rule_map).Error

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
