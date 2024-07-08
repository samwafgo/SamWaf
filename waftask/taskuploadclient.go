package waftask

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils/zlog"
	"SamWaf/wafsec"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	wafTokenInfoService = waf_service.WafTokenInfoServiceApp
)

func TaskClientToCenter() {
	zlog.Debug("TaskClientToCenter")

	if global.GWAF_CENTER_ENABLE == "false" {
		return
	}
	tokenInfo := wafTokenInfoService.GetOneAvailableInfo()
	if tokenInfo.Id == "" {
		return
	}

	// 准备要发送的数据
	data := request.CenterClientUpdateReq{
		ClientServerName:     global.GWAF_CUSTOM_SERVER_NAME,
		ClientUserCode:       global.GWAF_USER_CODE,
		ClientTenantId:       global.GWAF_TENANT_ID,
		ClientToken:          tokenInfo.AccessToken,
		ClientSsl:            "false",
		ClientPort:           strconv.Itoa(global.GWAF_LOCAL_SERVER_PORT),
		ClientNewVersion:     global.GWAF_RELEASE_VERSION,
		ClientNewVersionDesc: global.GWAF_RELEASE_VERSION_NAME,
		ClientSystemType:     runtime.GOOS,
		LastVisitTime:        customtype.JsonTime(time.Now()),
	}

	// 将数据编码为JSON格式
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}
	//加密
	encryptStr, _ := wafsec.AesEncrypt(jsonData, global.GWAF_COMMUNICATION_KEY)
	encryptContent := encryptStr
	/*zlog.Debug("注册加密前" + string(jsonData))
	zlog.Debug("注册加后" + encryptContent)*/
	// 创建请求URL
	url := global.GWAF_CENTER_URL + "/samwaf/center/update"

	// 创建一个HTTP请求
	req, err := http.NewRequest("POST", url, strings.NewReader(encryptContent))
	if err != nil {
		zlog.Debug("Error creating request:", err)
		return
	}

	// 设置请求的Content-Type为application/json
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 设置请求的Token
	//req.Header.Set("Authorization", "Bearer YOUR_TOKEN_HERE")

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		zlog.Debug("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		zlog.Debug("Error reading response body:", err)
		return
	}

	// 打印响应状态和响应体
	/*zlog.Debug("response Status:", resp.Status)
	zlog.Debug("response Body:", string(body))*/
}
