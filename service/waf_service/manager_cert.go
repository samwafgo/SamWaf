package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"crypto/tls"
	"os"
	"path/filepath"
)

// 管理端证书文件落地目录与文件名（与 api/waf_vpconfig_api.go 中 UploadSslCertApi 保持一致）
const (
	managerCertRelDir  = "data/ssl/manager"
	managerCertFile    = "domain.crt"
	managerKeyFile     = "domain.key"
	managerCertLogName = "ManagerCert"
)

// ManagerCertDir 返回管理端证书目录绝对路径
func ManagerCertDir() string {
	return filepath.Join(utils.GetCurrentDir(), "data", "ssl", "manager")
}

// RefreshManagerCertBySslConfig 当某个证书夹(SslConfig)条目被任一渠道更新后调用：
// 若管理端证书已绑定到该条目（global.GWAF_SSL_BIND_CERT_ID == sslConfigId），
// 则把新证书内容写入 data/ssl/manager/ 并触发管理端重启使其生效。
// 内容无变化时不做任何操作（避免无谓重启）。
func RefreshManagerCertBySslConfig(sslConfigId, certContent, keyContent string) {
	// 未绑定 或 绑定的不是当前更新的这张证书 → 与管理端无关
	if global.GWAF_SSL_BIND_CERT_ID == "" || global.GWAF_SSL_BIND_CERT_ID != sslConfigId {
		return
	}

	if certContent == "" || keyContent == "" {
		zlog.Warn(managerCertLogName, "绑定的证书内容为空，跳过管理端证书刷新")
		return
	}

	// 校验证书与私钥可配对，避免把坏证书写进管理端导致降级
	if _, err := tls.X509KeyPair([]byte(certContent), []byte(keyContent)); err != nil {
		zlog.Error(managerCertLogName, "绑定证书校验失败，跳过管理端证书刷新: "+err.Error())
		return
	}

	dir := ManagerCertDir()
	certPath := filepath.Join(dir, managerCertFile)
	keyPath := filepath.Join(dir, managerKeyFile)

	// 内容相同则不动
	if sameFileContent(certPath, certContent) && sameFileContent(keyPath, keyContent) {
		zlog.Debug(managerCertLogName, "管理端证书内容未变化，无需刷新")
		return
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		zlog.Error(managerCertLogName, "创建管理端证书目录失败: "+err.Error())
		return
	}
	if err := os.WriteFile(certPath, []byte(certContent), 0644); err != nil {
		zlog.Error(managerCertLogName, "写入管理端证书文件失败: "+err.Error())
		return
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0600); err != nil {
		zlog.Error(managerCertLogName, "写入管理端私钥文件失败: "+err.Error())
		return
	}

	zlog.Info(managerCertLogName, "管理端已绑定的证书发生更新，已刷新管理端证书并触发重启")

	// 非阻塞触发管理端重启，重启后 StartLocalServer 会按新证书重建监听器
	if global.GWAF_CHAN_MANAGER_RESTART != nil {
		select {
		case global.GWAF_CHAN_MANAGER_RESTART <- 1:
		default:
			// 已有重启请求在处理中
		}
	}
}

// sameFileContent 判断指定文件内容是否与给定内容一致（文件不存在视为不一致）
func sameFileContent(path, content string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return string(data) == content
}
