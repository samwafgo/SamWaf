package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafconfig"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type WafVpConfigApi struct {
}

// UpdateIpWhitelistApi 更新管理端IP白名单
// @Summary      更新管理端IP白名单
// @Description  更新管理端允许访问的IP白名单（CIDR格式，多个用逗号分隔）
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigIpWhitelistUpdateReq  true  "IP白名单配置"
// @Success      200   {object}  response.Response  "更新IP白名单成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateIpWhitelist [post]
func (w *WafVpConfigApi) UpdateIpWhitelistApi(c *gin.Context) {
	var req request.WafVpConfigIpWhitelistUpdateReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		// 调用配置文件更新函数
		err = wafconfig.UpdateIpWhitelist(req.IpWhitelist)
		if err != nil {
			response.FailWithMessage("更新IP白名单失败: "+err.Error(), c)
		} else {
			response.OkWithMessage("更新IP白名单成功", c)
		}
	} else {
		response.FailWithMessage("解析请求失败", c)
	}
}

// GetIpWhitelistApi 获取管理端IP白名单
// @Summary      获取管理端IP白名单
// @Description  获取当前管理端允许访问的IP白名单配置
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取IP白名单成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getIpWhitelist [get]
func (w *WafVpConfigApi) GetIpWhitelistApi(c *gin.Context) {
	// 直接从全局变量获取IP白名单
	ipWhitelist := global.GWAF_IP_WHITELIST

	// 构造响应数据
	resp := response2.WafVpConfigIpWhitelistGetResp{
		IpWhitelist: ipWhitelist,
	}

	response.OkWithDetailed(resp, "获取IP白名单成功", c)
}

// UpdateSslEnableApi 更新管理端SSL启用状态
// @Summary      更新管理端SSL启用状态
// @Description  开启或关闭管理端HTTPS，修改后需重启管理端生效
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigSslEnableUpdateReq  true  "SSL启用配置"
// @Success      200   {object}  response.Response  "更新SSL启用状态成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateSslEnable [post]
func (w *WafVpConfigApi) UpdateSslEnableApi(c *gin.Context) {
	var req request.WafVpConfigSslEnableUpdateReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 调用配置文件更新函数
		err = wafconfig.UpdateSslEnable(req.SslEnable)
		if err != nil {
			response.FailWithMessage("更新SSL启用状态失败: "+err.Error(), c)
		} else {
			response.OkWithMessage("更新SSL启用状态成功，需要重启管理端生效", c)
		}
	} else {
		response.FailWithMessage("解析请求失败", c)
	}
}

// GetSslStatusApi 获取管理端SSL状态
// @Summary      获取管理端SSL状态
// @Description  获取管理端SSL启用状态及证书信息（证书内容、域名、到期时间）
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取SSL状态成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getSslStatus [get]
func (w *WafVpConfigApi) GetSslStatusApi(c *gin.Context) {
	// 获取SSL启用状态
	sslEnable := global.GWAF_SSL_ENABLE

	// 检查证书文件是否存在
	certPath := filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager", "domain.crt")
	keyPath := filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager", "domain.key")

	hasCert := false
	certExpireAt := ""
	certDomain := ""
	certContent := ""
	keyContent := ""

	// 检查证书文件是否存在
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			hasCert = true
			// 读取证书文件获取证书信息
			certInfo := getCertInfo(certPath)
			certExpireAt = certInfo.ExpireAt
			certDomain = certInfo.Domain

			// 读取证书内容
			if certData, err := os.ReadFile(certPath); err == nil {
				certContent = string(certData)
			}

			// 读取私钥内容
			if keyData, err := os.ReadFile(keyPath); err == nil {
				keyContent = string(keyData)
			}
		}
	}

	// 构造响应数据
	resp := response2.WafVpConfigSslStatusGetResp{
		SslEnable:    sslEnable,
		HasCert:      hasCert,
		CertExpireAt: certExpireAt,
		CertDomain:   certDomain,
		CertContent:  certContent,
		KeyContent:   keyContent,
	}

	response.OkWithDetailed(resp, "获取SSL状态成功", c)
}

// UploadSslCertApi 上传管理端SSL证书
// @Summary      上传管理端SSL证书
// @Description  上传PEM格式的证书和私钥，校验通过后保存到 data/ssl/manager 目录，需重启生效
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigSslUploadReq  true  "证书配置"
// @Success      200   {object}  response.Response  "上传SSL证书成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/uploadSslCert [post]
func (w *WafVpConfigApi) UploadSslCertApi(c *gin.Context) {
	var req request.WafVpConfigSslUploadReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	// 验证证书内容不为空
	if req.CertContent == "" || req.KeyContent == "" {
		response.FailWithMessage("证书内容和私钥内容不能为空", c)
		return
	}

	// 校验证书可用性
	if err := validateCertificate(req.CertContent, req.KeyContent); err != nil {
		response.FailWithMessage("证书校验失败: "+err.Error(), c)
		return
	}

	// 创建目录
	sslDir := filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		response.FailWithMessage("创建证书目录失败: "+err.Error(), c)
		return
	}

	// 保存证书文件
	certPath := filepath.Join(sslDir, "domain.crt")
	keyPath := filepath.Join(sslDir, "domain.key")

	// 写入证书文件
	if err := os.WriteFile(certPath, []byte(req.CertContent), 0644); err != nil {
		response.FailWithMessage("保存证书文件失败: "+err.Error(), c)
		return
	}

	// 写入私钥文件
	if err := os.WriteFile(keyPath, []byte(req.KeyContent), 0600); err != nil {
		// 如果私钥保存失败，删除证书文件
		os.Remove(certPath)
		response.FailWithMessage("保存私钥文件失败: "+err.Error(), c)
		return
	}

	response.OkWithMessage("上传SSL证书成功，需要重启管理端生效", c)
}

// validateCertificate 校验证书可用性
func validateCertificate(certContent, keyContent string) error {
	// 解析证书
	certBlock, _ := pem.Decode([]byte(certContent))
	if certBlock == nil {
		return fmt.Errorf("无效的证书格式")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("解析证书失败: %v", err)
	}

	// 检查证书是否过期
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期")
	}

	// 解析私钥
	keyBlock, _ := pem.Decode([]byte(keyContent))
	if keyBlock == nil {
		return fmt.Errorf("无效的私钥格式")
	}

	// 尝试加载证书和私钥配对
	_, err = tls.X509KeyPair([]byte(certContent), []byte(keyContent))
	if err != nil {
		return fmt.Errorf("证书和私钥不匹配: %v", err)
	}

	return nil
}

// CertInfo 证书信息
type CertInfo struct {
	ExpireAt string // 过期时间
	Domain   string // 域名
}

// getCertInfo 获取证书信息
func getCertInfo(certPath string) CertInfo {
	info := CertInfo{
		ExpireAt: "",
		Domain:   "",
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return info
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return info
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return info
	}

	// 获取过期时间
	info.ExpireAt = cert.NotAfter.Format("2006-01-02 15:04:05")

	// 获取域名信息
	if cert.Subject.CommonName != "" {
		info.Domain = cert.Subject.CommonName
	}

	// 如果有SAN（Subject Alternative Name），优先使用
	if len(cert.DNSNames) > 0 {
		// 将所有域名用逗号连接
		info.Domain = ""
		for i, dns := range cert.DNSNames {
			if i > 0 {
				info.Domain += ", "
			}
			info.Domain += dns
		}
	}

	// 检查是否有IP地址
	if len(cert.IPAddresses) > 0 {
		if info.Domain == "" {
			// 如果没有域名，直接使用IP
			for i, ip := range cert.IPAddresses {
				if i > 0 {
					info.Domain += ", "
				}
				info.Domain += ip.String()
			}
		} else {
			// 如果已经有域名，追加IP
			for _, ip := range cert.IPAddresses {
				info.Domain += ", " + ip.String()
			}
		}
	}

	return info
}

// GetSecurityEntryApi 获取安全路径入口配置
// @Summary      获取安全路径入口配置
// @Description  获取当前安全路径入口的启用状态及访问码
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getSecurityEntry [get]
func (w *WafVpConfigApi) GetSecurityEntryApi(c *gin.Context) {
	resp := response2.WafVpConfigSecurityEntryGetResp{
		EntryEnable: global.GWAF_SECURITY_ENTRY_ENABLE,
		EntryPath:   global.GWAF_SECURITY_ENTRY_PATH,
	}
	response.OkWithDetailed(resp, "获取成功", c)
}

// UpdateSecurityEntryApi 更新安全路径入口配置
// @Summary      更新安全路径入口配置
// @Description  开启/关闭安全路径入口，路径为空时自动生成18位随机码，立即生效无需重启
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigSecurityEntryUpdateReq  true  "安全路径配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateSecurityEntry [post]
func (w *WafVpConfigApi) UpdateSecurityEntryApi(c *gin.Context) {
	var req request.WafVpConfigSecurityEntryUpdateReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	err = wafconfig.UpdateSecurityEntry(req.EntryEnable, req.EntryPath)
	if err != nil {
		response.FailWithMessage("更新安全路径配置失败: "+err.Error(), c)
		return
	}
	resp := response2.WafVpConfigSecurityEntryGetResp{
		EntryEnable: global.GWAF_SECURITY_ENTRY_ENABLE,
		EntryPath:   global.GWAF_SECURITY_ENTRY_PATH,
	}
	response.OkWithDetailed(resp, "更新安全路径配置成功", c)
}

// RestartManagerApi 重启管理端
// @Summary      重启管理端
// @Description  触发管理端1秒后重启，请等待5-10秒后重新访问
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "管理端将在1秒后重启"
// @Security     ApiKeyAuth
// @Router       /vipconfig/restartManager [post]
func (w *WafVpConfigApi) RestartManagerApi(c *gin.Context) {
	response.OkWithMessage("管理端将在1秒后重启，请稍候5-10秒后重新访问", c)

	// 延迟后重启，给时间返回响应
	go func() {
		time.Sleep(1 * time.Second)

		// 触发重启通道
		if global.GWAF_CHAN_MANAGER_RESTART != nil {
			select {
			case global.GWAF_CHAN_MANAGER_RESTART <- 1:
				// 发送成功
			default:
				// 通道已满，说明已经有重启请求在处理中
			}
		}
	}()
}
