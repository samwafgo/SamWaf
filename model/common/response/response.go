package response

import (
	"SamWaf/global"
	"SamWaf/wafsec"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Response struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
	Msg  string      `json:"msg"`
}

const (
	ERROR             = -1
	SUCCESS           = 0
	INPUT_SECRET_CODE = -2
	NEED_BIND_2FA     = -3
	NEED_CHANGE_PWD   = -4
	// NEED_REHANDSHAKE 告诉客户端本次没有可用的会话密钥，请重新握手后重试。
	// 只在 legacy 通道被运维关掉时出现（开着的话直接回落 legacy，旧客户端无感）。
	NEED_REHANDSHAKE = -5
	// BACKEND_UNAVAILABLE 依赖的存储/缓存后端本次不可用，请求未能完成。
	// 与 AUTHFAIL 的区别：登录状态没有问题，客户端应保留登录态并稍后重试。
	BACKEND_UNAVAILABLE = -6
	FORBIDDEN           = -403
	AUTHFAIL            = -999
)

// HeaderKeyID 是客户端声明本次会话密钥的请求头，与 X-Sec-Ver: 2 配套。
const HeaderKeyID = "X-Key-Id"

func Result(code int, data interface{}, msg string, c *gin.Context) {
	// OpenAPI 请求直接返回明文 JSON，不做 AES 加密
	if isOpenApi, exists := c.Get("is_openapi"); exists && isOpenApi == true {
		c.JSON(http.StatusOK, Response{
			code,
			data,
			msg,
		})
		return
	}
	result, _ := json.Marshal(data) //将数据转换为json

	// v2 客户端：用本次会话密钥加密（swt2）。会话失效（服务端重启/过期）时不报错，
	// 按下面的 legacy 分支回落——客户端能解开，并据此自行重新握手。
	keyid := ""
	if c.Request != nil {
		keyid = c.Request.Header.Get(HeaderKeyID)
	}
	if keyid != "" {
		if encryptStr, err := wafsec.TransportEncrypt(keyid, result); err == nil {
			c.JSON(http.StatusOK, Response{
				code,
				encryptStr,
				msg,
			})
			return
		}
	}

	// 关掉 legacy 的前提是 v2 确实可用；传输密钥没初始化成功时仍走 legacy，
	// 否则管理端会两条通道都不通，等于把自己锁在门外。
	if !global.GCONFIG_COMM_LEGACY_KEY && wafsec.CommKeyReady() {
		// legacy 通道已被关闭：给出可诊断的明文信号，而不是发一段对方解不开的密文
		c.JSON(http.StatusOK, Response{
			NEED_REHANDSHAKE,
			"",
			"会话密钥不可用，请重新握手",
		})
		return
	}

	encryptStr, _ := wafsec.AesEncrypt(result, global.GWAF_COMMUNICATION_KEY)
	// 开始时间
	c.JSON(http.StatusOK, Response{
		code,
		encryptStr,
		msg,
	})
}

// OkWithPlainData 返回不加密的 data，供握手类接口使用——此时双方还没有共享密钥。
func OkWithPlainData(data interface{}, c *gin.Context) {
	c.JSON(http.StatusOK, Response{
		SUCCESS,
		data,
		"查询成功",
	})
}

// FailWithPlainMessage 与 OkWithPlainData 配套的失败返回（同样不加密）。
func FailWithPlainMessage(message string, c *gin.Context) {
	c.JSON(http.StatusOK, Response{
		ERROR,
		"",
		message,
	})
}

func Ok(c *gin.Context) {
	Result(SUCCESS, map[string]interface{}{}, "操作成功", c)
}

func OkWithMessage(message string, c *gin.Context) {
	Result(SUCCESS, map[string]interface{}{}, message, c)
}

func OkWithData(data interface{}, c *gin.Context) {
	Result(SUCCESS, data, "查询成功", c)
}

func OkWithDetailed(data interface{}, message string, c *gin.Context) {
	Result(SUCCESS, data, message, c)
}

func Fail(c *gin.Context) {
	Result(ERROR, map[string]interface{}{}, "操作失败", c)
}

func FailWithMessage(message string, c *gin.Context) {
	Result(ERROR, map[string]interface{}{}, message, c)
}

func FailWithDetailed(data interface{}, message string, c *gin.Context) {
	Result(ERROR, data, message, c)
}
func AuthFailWithMessage(message string, c *gin.Context) {
	Result(AUTHFAIL, map[string]interface{}{}, message, c)
}

// ForbiddenWithMessage 已认证但无权限（角色不满足），不触发重新登录
func ForbiddenWithMessage(message string, c *gin.Context) {
	Result(FORBIDDEN, map[string]interface{}{}, message, c)
}

// BackendUnavailableWithMessage 后端存储本次不可用，登录状态不受影响，客户端保留登录态稍后重试
func BackendUnavailableWithMessage(message string, c *gin.Context) {
	Result(BACKEND_UNAVAILABLE, map[string]interface{}{}, message, c)
}
func SecretCodeFailWithMessage(message string, c *gin.Context) {
	Result(INPUT_SECRET_CODE, map[string]interface{}{}, message, c)
}
func NeedBind2FAWithMessage(message string, c *gin.Context) {
	Result(NEED_BIND_2FA, map[string]interface{}{}, message, c)
}

// NeedChangePwdWithMessage 令牌需强制改密：前端据此码引导用户先改密后再操作
func NeedChangePwdWithMessage(message string, c *gin.Context) {
	Result(NEED_CHANGE_PWD, map[string]interface{}{}, message, c)
}
