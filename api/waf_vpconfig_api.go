package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafconfig"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	if err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	// 防护1：不允许提交空白名单，避免所有人被锁在外面
	if strings.TrimSpace(req.IpWhitelist) == "" {
		response.FailWithMessage("IP白名单不能为空，否则将无法访问管理端", c)
		return
	}

	// 防护2：新白名单必须包含当前请求方的 IP，防止把自己锁在外面
	// 用 GetManageClientIP 与 IP 白名单中间件的强制点保持同源，避免"看得到却锁得住"的不一致自锁
	clientIP := utils.GetManageClientIP(c)
	entries := strings.Split(req.IpWhitelist, ",")
	selfIncluded := false
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			// CIDR 格式
			_, ipNet, cidrErr := net.ParseCIDR(entry)
			if cidrErr == nil && ipNet.Contains(net.ParseIP(clientIP)) {
				selfIncluded = true
				break
			}
		} else if entry == clientIP {
			selfIncluded = true
			break
		}
	}
	if !selfIncluded {
		response.FailWithMessage(fmt.Sprintf("当前访问IP(%s)不在新白名单中，保存后将无法访问管理端，请先将自己的IP加入白名单", clientIP), c)
		return
	}

	// 调用配置文件更新函数
	err = wafconfig.UpdateIpWhitelist(req.IpWhitelist)
	if err != nil {
		response.FailWithMessage("更新IP白名单失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("更新IP白名单成功", c)
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

// GetManageTrustedProxiesApi 获取管理端可信代理网段
// @Summary      获取管理端可信代理网段
// @Description  获取当前管理端可信代理网段（CIDR/IP，逗号分隔）
// @Tags         管理端配置
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getManageTrustedProxies [get]
func (w *WafVpConfigApi) GetManageTrustedProxiesApi(c *gin.Context) {
	resp := response2.WafVpConfigManageTrustedProxiesGetResp{
		TrustedProxies: global.GCONFIG_MANAGE_TRUSTED_PROXIES,
	}
	response.OkWithDetailed(resp, "获取管理端可信代理网段成功", c)
}

// UpdateManageTrustedProxiesApi 更新管理端可信代理网段
// @Summary      更新管理端可信代理网段
// @Description  仅当管理请求的直连对端落在此网段内，才采信代理头识别真实客户端；留空=不信任任何代理头。存 conf/config.yml，被白名单挡住时可改文件+重启自救
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigManageTrustedProxiesUpdateReq  true  "可信代理网段配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateManageTrustedProxies [post]
func (w *WafVpConfigApi) UpdateManageTrustedProxiesApi(c *gin.Context) {
	var req request.WafVpConfigManageTrustedProxiesUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	// 校验每个条目是合法 CIDR 或 IP（留空=不信任任何代理头，允许）
	for _, entry := range strings.Split(req.TrustedProxies, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				response.FailWithMessage(fmt.Sprintf("非法的CIDR: %s", entry), c)
				return
			}
		} else if net.ParseIP(entry) == nil {
			response.FailWithMessage(fmt.Sprintf("非法的IP: %s", entry), c)
			return
		}
	}
	if err := wafconfig.UpdateManageTrustedProxies(req.TrustedProxies); err != nil {
		response.FailWithMessage("更新管理端可信代理网段失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("更新管理端可信代理网段成功", c)
	}
}

// GetCorsAllowOriginsApi 获取 CORS 跨域来源白名单
func (w *WafVpConfigApi) GetCorsAllowOriginsApi(c *gin.Context) {
	resp := response2.WafVpConfigCorsAllowOriginsGetResp{
		CorsAllowOrigins: global.GCONFIG_CORS_ALLOW_ORIGINS,
	}
	response.OkWithDetailed(resp, "获取CORS跨域白名单成功", c)
}

// UpdateCorsAllowOriginsApi 更新 CORS 跨域来源白名单
// 回环/本机来源始终放行，此处仅配置额外的跨域来源；留空=仅放行回环。存 conf/config.yml，跨域配错连不上时可改文件+重启自救。
func (w *WafVpConfigApi) UpdateCorsAllowOriginsApi(c *gin.Context) {
	var req request.WafVpConfigCorsAllowOriginsUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	// 校验每个条目是合法来源(scheme://host[:port])；留空=仅放行回环，允许
	for _, entry := range strings.Split(req.CorsAllowOrigins, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			response.FailWithMessage(fmt.Sprintf("非法的来源(需形如 https://example.com[:端口]): %s", entry), c)
			return
		}
	}
	if err := wafconfig.UpdateCorsAllowOrigins(req.CorsAllowOrigins); err != nil {
		response.FailWithMessage("更新CORS跨域白名单失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("更新CORS跨域白名单成功", c)
	}
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

// GetNoticeTitleApi 获取通知标题前缀
// @Summary      获取通知标题前缀
// @Description  获取当前通知消息的标题前缀，用于区分多个 SamWaf 实例
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getNoticeTitle [get]
func (w *WafVpConfigApi) GetNoticeTitleApi(c *gin.Context) {
	resp := response2.WafVpConfigNoticeTitleGetResp{
		NoticeTitle: global.GWAF_NOTICE_TITLE,
	}
	response.OkWithDetailed(resp, "获取成功", c)
}

// UpdateNoticeTitleApi 更新通知标题前缀
// @Summary      更新通知标题前缀
// @Description  更新通知消息的标题前缀，立即生效无需重启，用于区分多个 SamWaf 实例
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigNoticeTitleUpdateReq  true  "通知标题配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateNoticeTitle [post]
func (w *WafVpConfigApi) UpdateNoticeTitleApi(c *gin.Context) {
	var req request.WafVpConfigNoticeTitleUpdateReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	err = wafconfig.UpdateNoticeTitle(req.NoticeTitle)
	if err != nil {
		response.FailWithMessage("更新通知标题失败: "+err.Error(), c)
		return
	}
	resp := response2.WafVpConfigNoticeTitleGetResp{
		NoticeTitle: global.GWAF_NOTICE_TITLE,
	}
	response.OkWithDetailed(resp, "更新通知标题成功", c)
}

// GetDomainWhitelistApi 获取管理端域名白名单
// @Summary      获取管理端域名白名单
// @Description  获取当前管理端允许访问的域名白名单配置
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取域名白名单成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getDomainWhitelist [get]
func (w *WafVpConfigApi) GetDomainWhitelistApi(c *gin.Context) {
	resp := response2.WafVpConfigDomainWhitelistGetResp{
		DomainWhitelist: global.GWAF_DOMAIN_WHITELIST,
	}
	response.OkWithDetailed(resp, "获取域名白名单成功", c)
}

// UpdateDomainWhitelistApi 更新管理端域名白名单
// @Summary      更新管理端域名白名单
// @Description  更新管理端允许访问的域名白名单（多个域名用逗号分隔，为空表示不限制）
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigDomainWhitelistUpdateReq  true  "域名白名单配置"
// @Success      200   {object}  response.Response  "更新域名白名单成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateDomainWhitelist [post]
func (w *WafVpConfigApi) UpdateDomainWhitelistApi(c *gin.Context) {
	var req request.WafVpConfigDomainWhitelistUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	// 若白名单非空，当前访问域名必须在列表中，防止把自己锁在外面
	if strings.TrimSpace(req.DomainWhitelist) != "" {
		host := c.Request.Host
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}
		selfIncluded := false
		for _, d := range strings.Split(req.DomainWhitelist, ",") {
			if strings.TrimSpace(d) == hostname {
				selfIncluded = true
				break
			}
		}
		if !selfIncluded {
			response.FailWithMessage(fmt.Sprintf("当前访问域名(%s)不在新白名单中，保存后将无法访问管理端，请先将当前域名加入白名单", hostname), c)
			return
		}
	}

	if err := wafconfig.UpdateDomainWhitelist(req.DomainWhitelist); err != nil {
		response.FailWithMessage("更新域名白名单失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("更新域名白名单成功", c)
	}
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

// GetSslForceHttpsApi 获取管理端仅允许HTTPS开关
// @Summary      获取管理端仅允许HTTPS开关
// @Description  获取管理端是否仅允许HTTPS访问
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getSslForceHttps [get]
func (w *WafVpConfigApi) GetSslForceHttpsApi(c *gin.Context) {
	resp := response2.WafVpConfigSslForceHttpsGetResp{
		ForceHttps: global.GWAF_SSL_FORCE_HTTPS,
	}
	response.OkWithDetailed(resp, "获取成功", c)
}

// UpdateSslForceHttpsApi 更新管理端仅允许HTTPS开关
// @Summary      更新管理端仅允许HTTPS开关
// @Description  开启后管理端纯HTTP请求将301跳转到HTTPS（仅在已启用SSL且证书有效时生效），需重启管理端生效
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigSslForceHttpsUpdateReq  true  "仅HTTPS配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateSslForceHttps [post]
func (w *WafVpConfigApi) UpdateSslForceHttpsApi(c *gin.Context) {
	var req request.WafVpConfigSslForceHttpsUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	if err := wafconfig.UpdateSslForceHttps(req.ForceHttps); err != nil {
		response.FailWithMessage("更新仅HTTPS开关失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("更新成功，需要重启管理端生效", c)
}

// GetSslBindCertApi 获取管理端证书绑定的证书夹
// @Summary      获取管理端证书绑定的证书夹
// @Description  获取管理端证书当前绑定的证书夹ID及其摘要信息
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/getSslBindCert [get]
func (w *WafVpConfigApi) GetSslBindCertApi(c *gin.Context) {
	resp := response2.WafVpConfigSslBindCertGetResp{
		SslConfigId: global.GWAF_SSL_BIND_CERT_ID,
	}
	if global.GWAF_SSL_BIND_CERT_ID != "" {
		bean := wafSslConfigService.GetDetailInner(global.GWAF_SSL_BIND_CERT_ID)
		if bean.Id != "" {
			resp.Domains = bean.Domains
			resp.ValidTo = time.Time(bean.ValidTo).Format("2006-01-02 15:04:05")
		}
	}
	response.OkWithDetailed(resp, "获取成功", c)
}

// UpdateSslBindCertApi 绑定/解绑管理端证书到证书夹
// @Summary      绑定/解绑管理端证书到证书夹
// @Description  把管理端证书绑定到指定证书夹条目；绑定后该证书夹经任一渠道更新时管理端证书会自动同步并重启。ssl_config_id 传空表示解绑（回到手动上传模式）。
// @Tags         管理端配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafVpConfigSslBindCertUpdateReq  true  "绑定配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /vipconfig/updateSslBindCert [post]
func (w *WafVpConfigApi) UpdateSslBindCertApi(c *gin.Context) {
	var req request.WafVpConfigSslBindCertUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}

	// 解绑：清空绑定，保留当前已落地的管理端证书文件（手动上传模式）
	if strings.TrimSpace(req.SslConfigId) == "" {
		if err := wafconfig.UpdateSslBindCertId(""); err != nil {
			response.FailWithMessage("解绑失败: "+err.Error(), c)
			return
		}
		response.OkWithMessage("已解绑管理端证书，回到手动上传模式", c)
		return
	}

	// 绑定：校验证书夹内容可用
	bean := wafSslConfigService.GetDetailInner(req.SslConfigId)
	if bean.Id == "" {
		response.FailWithMessage("指定的证书夹不存在", c)
		return
	}
	if bean.CertContent == "" || bean.KeyContent == "" {
		response.FailWithMessage("该证书夹证书或私钥内容为空，无法绑定", c)
		return
	}
	if err := validateCertificate(bean.CertContent, bean.KeyContent); err != nil {
		response.FailWithMessage("证书校验失败: "+err.Error(), c)
		return
	}

	// 先持久化绑定关系（设置全局变量），再复用刷新钩子立即落地并触发重启
	if err := wafconfig.UpdateSslBindCertId(req.SslConfigId); err != nil {
		response.FailWithMessage("保存绑定关系失败: "+err.Error(), c)
		return
	}
	waf_service.RefreshManagerCertBySslConfig(bean.Id, bean.CertContent, bean.KeyContent)

	response.OkWithMessage("绑定成功，管理端证书将更新并自动重启，请稍候5-10秒后重新访问", c)
}
