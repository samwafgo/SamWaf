package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
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

// EchoErrorInfo  ruleName 对内记录  blockInfo 对外展示
func EchoErrorInfo(w http.ResponseWriter, r *http.Request, weblogbean innerbean.WebLog, ruleName string, blockInfo string, hostsafe *wafenginmodel.HostSafe, globalHostSafe *wafenginmodel.HostSafe, isLog bool) {
	resBytes := []byte("")
	var responseCode int = 403

	renderData := map[string]interface{}{
		"SAMWAF_REQ_UUID":   weblogbean.REQ_UUID,
		"SAMWAF_BLOCK_INFO": blockInfo,
	}

	// 处理 hostsafe 的模板
	if blockingPage, ok := hostsafe.BlockingPage["other_block"]; ok {
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
	} else if globalBlockingPage, ok := globalHostSafe.BlockingPage["other_block"]; ok {
		// 处理 globalHostSafe 的模板
		// 设置 HTTP header
		var headers []map[string]string
		if err := json.Unmarshal([]byte(globalBlockingPage.ResponseHeader), &headers); err == nil {
			for _, header := range headers {
				if name, ok := header["name"]; ok {
					if value, ok := header["value"]; ok && value != "" {
						w.Header().Set(name, value)
					}
				}
			}
		}

		// 渲染模板
		renderedBytes, err := renderTemplate(globalBlockingPage.ResponseContent, renderData)
		if err == nil {
			resBytes = renderedBytes
		} else {
			resBytes = []byte(globalBlockingPage.ResponseContent)
		}
		// 设置响应码
		if code, err := strconv.Atoi(globalBlockingPage.ResponseCode); err == nil {
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
		weblogbean.STATUS_CODE = 403
		weblogbean.TASK_FLAG = 1
		weblogbean.GUEST_IDENTIFICATION = "可疑用户"
		global.GQEQUE_LOG_DB.Enqueue(weblogbean)
	}
}
