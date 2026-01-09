package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strconv"
	"text/template"
	"time"
)

func renderTemplate(templateContent string, data map[string]interface{}) ([]byte, error) {
	tmpl, err := template.New("blockingPageTemplate").Delims("[[", "]]").Parse(templateContent)
	if err != nil {
		return nil, err
	}

	var renderedCode bytes.Buffer
	err = tmpl.Execute(&renderedCode, data)
	if err != nil {
		return nil, err
	}

	return renderedCode.Bytes(), nil
}

// EchoErrorInfo  ruleName 对内记录  blockInfo 对外展示  attackType 攻击类型
func EchoErrorInfo(w http.ResponseWriter, r *http.Request, weblogbean *innerbean.WebLog, ruleName string, blockInfo string, hostsafe *wafenginmodel.HostSafe, globalHostSafe *wafenginmodel.HostSafe, isLog bool, attackType string) {
	resBytes := []byte("")
	var responseCode int = 403

	renderData := map[string]interface{}{
		"SAMWAF_REQ_UUID":   weblogbean.REQ_UUID,
		"SAMWAF_BLOCK_INFO": blockInfo,
	}

	// 优先根据攻击类型查找对应的拦截页面
	var blockingPage model.BlockingPage
	var ok bool

	// 1. 优先查找网站级别的攻击类型专属拦截页面
	if attackType != "" {
		for _, page := range hostsafe.BlockingPage {
			if page.AttackType == attackType {
				blockingPage = page
				ok = true
				break
			}
		}
	}

	// 2. 如果没找到攻击类型专属页面，尝试使用响应码为403的通用拦截页面
	if !ok {
		blockingPage, ok = hostsafe.BlockingPage["403"]
	}

	// 3. 如果网站级别没找到，查找全局级别的攻击类型专属页面
	if !ok && attackType != "" {
		for _, page := range globalHostSafe.BlockingPage {
			if page.AttackType == attackType {
				blockingPage = page
				ok = true
				break
			}
		}
	}

	// 4. 如果还没找到，使用全局的403拦截页面
	if !ok {
		blockingPage, ok = globalHostSafe.BlockingPage["403"]
	}

	if ok {
		// 设置 HTTP header
		var headers []map[string]string
		if err := json.Unmarshal([]byte(blockingPage.ResponseHeader), &headers); err == nil {
			for _, header := range headers {
				if name, ok := header["name"]; ok {
					if value, ok := header["value"]; ok && value != "" {
						w.Header().Set(name, value)
					}
				}
			}
		}

		// 渲染模板
		renderedBytes, err := renderTemplate(blockingPage.ResponseContent, renderData)
		if err == nil {
			resBytes = renderedBytes
		} else {
			resBytes = []byte(blockingPage.ResponseContent)
		}

		// 设置响应码
		if code, err := strconv.Atoi(blockingPage.ResponseCode); err == nil {
			responseCode = code
		}
	} else {
		// 默认的阻止页面
		renderedBytes, err := renderTemplate(global.GLOBAL_DEFAULT_BLOCK_INFO, renderData)
		if err == nil {
			resBytes = renderedBytes
		} else {
			resBytes = []byte(global.GLOBAL_DEFAULT_BLOCK_INFO)
		}
	}

	// 特殊处理444状态码：直接关闭连接，不返回任何内容
	if responseCode == 444 {
		// 444状态码表示关闭连接，不返回任何响应
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
				// 记录日志
				if isLog {
					go func() {
						// 发送推送消息
						global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.RuleMessageInfo{
							BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: global.GWAF_CUSTOM_SERVER_NAME},
							Domain:          weblogbean.HOST,
							RuleInfo:        ruleName,
							Ip:              fmt.Sprintf("%s (%s)", weblogbean.SRC_IP, utils.GetCountry(weblogbean.SRC_IP)),
						})
					}()

					datetimeNow := time.Now()
					weblogbean.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
					weblogbean.RES_BODY = "444 Connection Closed"
					weblogbean.RULE = ruleName
					weblogbean.ACTION = "阻止"
					weblogbean.STATUS = "连接关闭"
					weblogbean.STATUS_CODE = 444
					weblogbean.TASK_FLAG = 1
					weblogbean.GUEST_IDENTIFICATION = "可疑用户"
					global.GQEQUE_LOG_DB.Enqueue(weblogbean)
				}
				return
			}
		}
		// 如果无法劫持连接，则降级为正常的403响应
		responseCode = 403
	}

	w.WriteHeader(responseCode)
	_, err := w.Write(resBytes)
	if err != nil {
		zlog.Debug("write fail:", zap.Any("", err))
		return
	}

	if isLog {
		go func() {
			// 发送推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.RuleMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Domain:          weblogbean.HOST,
				RuleInfo:        ruleName,
				Ip:              fmt.Sprintf("%s (%s)", weblogbean.SRC_IP, utils.GetCountry(weblogbean.SRC_IP)),
			})
		}()

		datetimeNow := time.Now()
		weblogbean.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
		// 记录响应body
		weblogbean.RES_BODY = string(resBytes)
		weblogbean.RULE = ruleName
		weblogbean.ACTION = "阻止"
		weblogbean.STATUS = "阻止访问"
		weblogbean.STATUS_CODE = responseCode
		weblogbean.TASK_FLAG = 1
		weblogbean.GUEST_IDENTIFICATION = "可疑用户"
		global.GQEQUE_LOG_DB.Enqueue(weblogbean)
	}
}

// EchoResponseErrorInfo  ruleName 对内记录  blockInfo 对外展示  attackType 攻击类型
func EchoResponseErrorInfo(resp *http.Response, weblogbean *innerbean.WebLog, ruleName string, blockInfo string, hostsafe *wafenginmodel.HostSafe, globalHostSafe *wafenginmodel.HostSafe, isLog bool, attackType string) {
	resBytes := []byte("")
	var responseCode int = 403

	renderData := map[string]interface{}{
		"SAMWAF_REQ_UUID":   weblogbean.REQ_UUID,
		"SAMWAF_BLOCK_INFO": blockInfo,
	}

	// 优先根据攻击类型查找对应的拦截页面
	var blockingPage model.BlockingPage
	var ok bool

	// 1. 优先查找网站级别的攻击类型专属拦截页面
	if attackType != "" {
		for _, page := range hostsafe.BlockingPage {
			if page.AttackType == attackType {
				blockingPage = page
				ok = true
				break
			}
		}
	}

	// 2. 如果没找到攻击类型专属页面，尝试使用响应码为403的通用拦截页面
	if !ok {
		blockingPage, ok = hostsafe.BlockingPage["403"]
	}

	// 3. 如果网站级别没找到，查找全局级别的攻击类型专属页面
	if !ok && attackType != "" {
		for _, page := range globalHostSafe.BlockingPage {
			if page.AttackType == attackType {
				blockingPage = page
				ok = true
				break
			}
		}
	}

	// 4. 如果还没找到，使用全局的403拦截页面
	if !ok {
		blockingPage, ok = globalHostSafe.BlockingPage["403"]
	}

	if ok {
		// 设置 HTTP header
		var headers []map[string]string
		if err := json.Unmarshal([]byte(blockingPage.ResponseHeader), &headers); err == nil {
			for _, header := range headers {
				if name, ok := header["name"]; ok {
					if value, ok := header["value"]; ok && value != "" {
						resp.Header.Set(name, value)
					}
				}
			}
		}

		// 渲染模板
		renderedBytes, err := renderTemplate(blockingPage.ResponseContent, renderData)
		if err == nil {
			resBytes = renderedBytes
		} else {
			resBytes = []byte(blockingPage.ResponseContent)
		}

		// 设置响应码
		if code, err := strconv.Atoi(blockingPage.ResponseCode); err == nil {
			responseCode = code
		}
	} else {
		// 默认的阻止页面
		renderedBytes, err := renderTemplate(global.GLOBAL_DEFAULT_BLOCK_INFO, renderData)
		if err == nil {
			resBytes = renderedBytes
		} else {
			resBytes = []byte(global.GLOBAL_DEFAULT_BLOCK_INFO)
		}
	}

	// 特殊处理444状态码：直接关闭连接
	if responseCode == 444 {
		// 444状态码表示关闭连接，设置空body
		resp.StatusCode = 444
		resp.Status = "444 Connection Closed Without Response"
		resp.Body = io.NopCloser(bytes.NewBuffer([]byte{}))
		resp.ContentLength = 0
		resp.Header.Set("Content-Length", "0")
		// 不设置Content-Type，让连接直接关闭

		if isLog {
			go func() {
				// 发送推送消息
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.RuleMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: global.GWAF_CUSTOM_SERVER_NAME},
					Domain:          weblogbean.HOST,
					RuleInfo:        ruleName,
					Ip:              fmt.Sprintf("%s (%s)", weblogbean.SRC_IP, utils.GetCountry(weblogbean.SRC_IP)),
				})
			}()

			datetimeNow := time.Now()
			weblogbean.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
			weblogbean.RES_BODY = "444 Connection Closed"
			weblogbean.RULE = ruleName
			weblogbean.ACTION = "阻止"
			weblogbean.STATUS = "连接关闭"
			weblogbean.STATUS_CODE = 444
			weblogbean.TASK_FLAG = 1
			weblogbean.GUEST_IDENTIFICATION = "可疑用户"
			global.GQEQUE_LOG_DB.Enqueue(weblogbean)
		}
		return
	}

	resp.StatusCode = responseCode

	resp.Body = io.NopCloser(bytes.NewBuffer(resBytes))

	// head 修改追加内容
	resp.ContentLength = int64(len(resBytes))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(resBytes)), 10))
	resp.Header.Set("Content-Type", "text/html;")
	if isLog {
		go func() {
			// 发送推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.RuleMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Domain:          weblogbean.HOST,
				RuleInfo:        ruleName,
				Ip:              fmt.Sprintf("%s (%s)", weblogbean.SRC_IP, utils.GetCountry(weblogbean.SRC_IP)),
			})
		}()

		datetimeNow := time.Now()
		weblogbean.TimeSpent = datetimeNow.UnixNano()/1e6 - weblogbean.UNIX_ADD_TIME
		// 记录响应body
		weblogbean.RES_BODY = string(resBytes)
		weblogbean.RULE = ruleName
		weblogbean.ACTION = "阻止"
		weblogbean.STATUS = "阻止访问"
		weblogbean.STATUS_CODE = responseCode
		weblogbean.TASK_FLAG = 1
		weblogbean.GUEST_IDENTIFICATION = "可疑用户"
		global.GQEQUE_LOG_DB.Enqueue(weblogbean)
	}
}
