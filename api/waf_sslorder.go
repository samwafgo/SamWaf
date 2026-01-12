package api

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSslOrderApi struct {
}

func (w *WafSslOrderApi) AddApi(c *gin.Context) {
	var req request.WafSslorderaddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		hostBean := wafHostService.GetDetailByCodeApi(req.HostCode)
		if hostBean.Id == "" {
			response.FailWithMessage("查找主机未找到", c)
			return
		}
		//检测是否有80端口
		if req.ApplyMethod == "http01" && w.check80Port(hostBean) == false {
			response.FailWithMessage("未在主机上找到80端口配置，请在绑定更多端口里面增加80端口，再进行发起", c)
			return
		}
		//检测是否*的情况
		if req.ApplyMethod == "http01" && hostBean.Host == "*" {
			response.FailWithMessage("未指定域名情况不能使用http文件验证方式", c)
			return
		}
		//检测是否是IP地址，IP地址只能使用http01验证方式
		isIpAddress := utils.IsIP(hostBean.Host)
		if isIpAddress && req.ApplyMethod != "http01" {
			response.FailWithMessage("IP证书只支持HTTP文件验证方式(http01)，不支持DNS验证方式", c)
			return
		}
		if req.ApplyPlatform == "zerossl" {

			if global.GCONFIG_ZEROSSL_EAB_KID == "" || global.GCONFIG_ZEROSSL_EAB_HMAC_KEY == "" {
				if global.GCONFIG_ZEROSSL_ACCESS_KEY == "" {
					response.FailWithMessage("请配置zerossl访问key,在系统配置中 zerossl_access_key 中配置", c)
					return
				}
				// 调用 ZeroSSL API 获取 EAB 凭证
				err := w.fetchAndUpdateZeroSSLEABCredentials()
				if err != nil {
					response.FailWithMessage(fmt.Sprintf("获取ZeroSSL EAB凭证失败: %s", err.Error()), c)
					return
				}
			}
		}
		addResult, err := wafSslOrderService.AddApi(req)
		if err == nil {
			w.NotifyWaf(enums.ChanSslOrderSubmitted, addResult)
			response.OkWithMessage("添加成功", c)
		} else {
			response.FailWithMessage("添加失败", c)
		}
		return

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSslOrderApi) GetDetailApi(c *gin.Context) {
	var req request.WafSslorderdetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSslOrderService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSslOrderApi) GetListApi(c *gin.Context) {
	var req request.WafSslordersearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafSslOrderService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSslOrderApi) DelApi(c *gin.Context) {
	var req request.WafSslorderdeleteReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSslOrderService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafSslOrderApi) ModifyApi(c *gin.Context) {
	var req request.WafSslordereditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		existingOrder := wafSslOrderService.GetDetailById(req.Id)
		if existingOrder.Id == "" {
			response.FailWithMessage("SSL订单不存在", c)
			return
		}

		if existingOrder.ApplyStatus != "success" {
			response.FailWithMessage("上次证书申请未成功，无法续期。请点击新建发起申请", c)
			return
		}
		if len(existingOrder.ResultPrivateKey) == 0 || len(existingOrder.ResultCertificate) == 0 {
			response.FailWithMessage("上次证书未找到，无法续期。请点击新建发起申请", c)
			return
		}
		isExpired, _, _, err := existingOrder.ExpirationMessage()
		if err != nil {
			response.FailWithMessage("无法获取证书到期信息："+err.Error()+",请点击新建发起申请", c)
			return
		}
		if isExpired {
			response.FailWithMessage("证书已过期，无法续期，请点击新建发起申请", c)
			return
		}

		err = wafSslOrderService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("续期发生错误", c)
		} else {
			//发起续期
			renewAdd, err := wafSslOrderService.RenewAdd(req.Id)
			if err == nil {
				w.NotifyWaf(enums.ChanSslOrderrenew, renewAdd)
				response.OkWithMessage("续期成功", c)
			} else {
				response.FailWithMessage("续期失败", c)
			}
		}
	} else {
		response.FailWithMessage("续期解析失败", c)
	}
}

/*
*
发送SSL证书订单通知
*/
func (w *WafSslOrderApi) NotifyWaf(chanType int, bean model.SslOrder) {
	var chanInfo = spec.ChanSslOrder{
		Type:    chanType,
		Content: bean,
	}
	global.GWAF_CHAN_SSLOrder <- chanInfo
}

// 检测是否有80端口
func (w *WafSslOrderApi) check80Port(hosts model.Hosts) bool {
	splitPort := strings.Split(hosts.BindMorePort, ",")

	for _, port := range splitPort {
		if port == "80" {
			return true
		}
	}
	if hosts.Port == 80 {
		return true
	}
	return false
}

// fetchAndUpdateZeroSSLEABCredentials 调用 ZeroSSL API 获取 EAB 凭证并更新配置
func (w *WafSslOrderApi) fetchAndUpdateZeroSSLEABCredentials() error {
	// 构建请求 URL
	apiURL := "https://api.zerossl.com/acme/eab-credentials"
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("解析URL失败: %w", err)
	}

	// 添加查询参数（GET 请求）
	q := u.Query()
	q.Set("access_key", global.GCONFIG_ZEROSSL_ACCESS_KEY)
	u.RawQuery = q.Encode()

	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	// 发送 POST 请求（URL 中包含查询参数）
	zlog.Info("调用 ZeroSSL API 获取 EAB 凭证", "url", u.String())
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 解析 JSON 响应
	var apiResponse struct {
		Success    bool   `json:"success"`
		EabKid     string `json:"eab_kid"`
		EabHmacKey string `json:"eab_hmac_key"`
		Error      *struct {
			Code    int    `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return fmt.Errorf("解析JSON响应失败: %w, 原始响应: %s", err, string(body))
	}

	// 检查 API 响应是否成功
	if !apiResponse.Success {
		errorMsg := string(body)
		if apiResponse.Error != nil {
			errorMsg = fmt.Sprintf("错误代码: %d, 类型: %s, 消息: %s",
				apiResponse.Error.Code, apiResponse.Error.Type, apiResponse.Error.Message)
		}
		return fmt.Errorf("API返回失败: %s", errorMsg)
	}

	// 验证返回的凭证是否有效
	if apiResponse.EabKid == "" || apiResponse.EabHmacKey == "" {
		return fmt.Errorf("API返回的凭证为空, 响应: %s", string(body))
	}

	// 更新全局变量
	global.GCONFIG_ZEROSSL_EAB_KID = apiResponse.EabKid
	global.GCONFIG_ZEROSSL_EAB_HMAC_KEY = apiResponse.EabHmacKey

	// 更新数据库配置
	// 更新 zerossl_eab_kid
	eabKidConfig := wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: "zerossl_eab_kid"})
	if eabKidConfig.Id != "" {
		err = wafSystemConfigService.ModifyApi(request.WafSystemConfigEditReq{
			Id:        eabKidConfig.Id,
			Item:      eabKidConfig.Item,
			ItemClass: eabKidConfig.ItemClass,
			Value:     apiResponse.EabKid,
			Remarks:   eabKidConfig.Remarks,
			ItemType:  eabKidConfig.ItemType,
			Options:   eabKidConfig.Options,
		})
		if err != nil {
			zlog.Warn("更新 zerossl_eab_kid 配置失败", "error", err.Error())
		}
	}

	// 更新 zerossl_eab_hmac_key
	eabHmacKeyConfig := wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: "zerossl_eab_hmac_key"})
	if eabHmacKeyConfig.Id != "" {
		err = wafSystemConfigService.ModifyApi(request.WafSystemConfigEditReq{
			Id:        eabHmacKeyConfig.Id,
			Item:      eabHmacKeyConfig.Item,
			ItemClass: eabHmacKeyConfig.ItemClass,
			Value:     apiResponse.EabHmacKey,
			Remarks:   eabHmacKeyConfig.Remarks,
			ItemType:  eabHmacKeyConfig.ItemType,
			Options:   eabHmacKeyConfig.Options,
		})
		if err != nil {
			zlog.Warn("更新 zerossl_eab_hmac_key 配置失败", "error", err.Error())
		}
	}

	zlog.Info("ZeroSSL EAB 凭证获取并更新成功")
	return nil
}
