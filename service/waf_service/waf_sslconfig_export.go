package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 证书导出（落盘）编排层。
//
// issue #929：SamWaf 申请/续期成功后，把证书同步成实体文件，供 nginx 等外部程序使用。
// 证书夹里的 CertPath/KeyPath 是「读进来」的方向，不能复用（复用会把用户的源文件反向
// 覆盖掉），所以用独立的 ExportCertPath/ExportKeyPath。
//
// 硬约束：导出是「附加动作」，无论校验不过、目录不存在、权限不足还是磁盘满，
// 都只记录状态和日志，绝不影响证书本身的申请/续期/加载/生效流程。

const (
	certExportFilePerm = 0o644 // 证书是公开信息
	keyExportFilePerm  = 0o600 // 私钥只给运行账号读
)

// ExportById 按证书夹ID把证书和私钥导出成实体文件。
//
// 之所以按 ID 重新查库而不是接收调用方手上的对象：ACME 续期路径传下来的是新构造的
// SslConfig（只填了证书内容），导出路径这些列是空的，直接用会误判成「未配置导出」。
//
// 返回 msg 为可展示的结果描述（未配置导出时为空串），err 非空表示导出失败。
func (receiver *WafSslConfigService) ExportById(id string) (msg string, err error) {
	// 兜底：导出挂在证书申请/加载的主流程上，这里出任何意外都不能把主流程带崩
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("证书导出内部异常: %v", r)
			msg = ""
			zlog.Error("SSLExport", fmt.Sprintf("证书夹[%s] 导出发生异常: %v", id, r))
		}
	}()

	if strings.TrimSpace(id) == "" {
		return "", errors.New("证书夹ID为空")
	}
	config := receiver.GetDetailInner(id)
	if config.Id == "" {
		return "", fmt.Errorf("证书夹不存在: %s", id)
	}
	return receiver.exportConfig(config)
}

// exportConfig 真正执行导出，并把结果写回 export_status 列供前端查看。
func (receiver *WafSslConfigService) exportConfig(config model.SslConfig) (string, error) {
	exportCert := strings.TrimSpace(config.ExportCertPath)
	exportKey := strings.TrimSpace(config.ExportKeyPath)

	// 两个都没填 = 该证书夹未开启导出，静默跳过（功能默认关闭）
	if exportCert == "" && exportKey == "" {
		return "", nil
	}

	certPath, keyPath, err := receiver.PrepareExportPaths(config.Id, config.CertPath, config.KeyPath, exportCert, exportKey)
	if err != nil {
		receiver.saveExportStatus(config.Id, "失败: "+err.Error())
		zlog.Error("SSLExport", fmt.Sprintf("证书夹[%s] 导出路径校验不通过: %v", config.Domains, err))
		return "", err
	}

	if config.CertContent == "" || config.KeyContent == "" {
		err = errors.New("证书或密钥内容为空，不导出")
		receiver.saveExportStatus(config.Id, "失败: "+err.Error())
		zlog.Warn("SSLExport", fmt.Sprintf("证书夹[%s] %v", config.Domains, err))
		return "", err
	}

	// 先写私钥再写证书：外部 reload 脚本通常盯着 .crt，先落私钥能保证证书出现时
	// 配对的私钥一定已经就位；私钥失败则证书不写，磁盘上仍是完整的旧的一对。
	keyWritten, err := utils.WriteCertFileAtomic(keyPath, []byte(config.KeyContent), keyExportFilePerm)
	if err != nil {
		err = fmt.Errorf("写入密钥文件失败: %v", err)
		receiver.saveExportStatus(config.Id, "失败: "+err.Error())
		zlog.Error("SSLExport", fmt.Sprintf("证书夹[%s] %v", config.Domains, err))
		return "", err
	}
	certWritten, err := utils.WriteCertFileAtomic(certPath, []byte(config.CertContent), certExportFilePerm)
	if err != nil {
		err = fmt.Errorf("写入证书文件失败: %v", err)
		receiver.saveExportStatus(config.Id, "失败: "+err.Error())
		zlog.Error("SSLExport", fmt.Sprintf("证书夹[%s] %v (密钥已更新=%v)", config.Domains, err, keyWritten))
		return "", err
	}

	var msg string
	if certWritten || keyWritten {
		msg = fmt.Sprintf("导出成功: %s , %s", certPath, keyPath)
	} else {
		msg = fmt.Sprintf("文件内容已是最新，无需重写: %s , %s", certPath, keyPath)
	}
	receiver.saveExportStatus(config.Id, msg)
	zlog.Info("SSLExport", fmt.Sprintf("证书夹[%s] %s", config.Domains, msg))
	return msg, nil
}

// PrepareExportPaths 校验导出路径（保存时和导出时都走这里），返回规范化后的路径。
// 两个路径都为空表示未开启导出，返回两个空串且不报错。
//
// selfId 为空表示新增场景（库里还没有这条记录）。
func (receiver *WafSslConfigService) PrepareExportPaths(selfId, loadCertPath, loadKeyPath, exportCertPath, exportKeyPath string) (string, string, error) {
	exportCertPath = strings.TrimSpace(exportCertPath)
	exportKeyPath = strings.TrimSpace(exportKeyPath)
	if exportCertPath == "" && exportKeyPath == "" {
		return "", "", nil
	}
	// 只填一个没有意义：外部程序拿到证书却没有配对的私钥用不了
	if exportCertPath == "" || exportKeyPath == "" {
		return "", "", errors.New("导出证书路径和导出密钥路径必须同时填写")
	}

	certPath, err := utils.ValidateCertExportPath(exportCertPath, utils.CertExportCert)
	if err != nil {
		return "", "", fmt.Errorf("导出证书路径不合法: %v", err)
	}
	keyPath, err := utils.ValidateCertExportPath(exportKeyPath, utils.CertExportKey)
	if err != nil {
		return "", "", fmt.Errorf("导出密钥路径不合法: %v", err)
	}
	if utils.IsSameFilePath(certPath, keyPath) {
		return "", "", errors.New("导出证书路径和导出密钥路径不能相同")
	}

	// 不能导出到「加载路径」上：那是读入方向，写过去会形成自我覆盖，
	// 用户放在那里的源文件会被 SamWaf 反向改掉。
	// 加载路径是「读入」方向、走 SamWaf 自管的 ssl/<id>/ 或用户自填，不受导出允许目录约束；
	// 这里只需判是否与导出目标撞车（IsSameFilePath 自带 Clean/大小写归一），不做导出策略校验。
	for _, loadPath := range []string{loadCertPath, loadKeyPath} {
		lp := strings.TrimSpace(loadPath)
		if lp == "" {
			continue
		}
		if utils.IsSameFilePath(lp, certPath) || utils.IsSameFilePath(lp, keyPath) {
			return "", "", fmt.Errorf("导出路径不能和本证书夹的自动加载路径相同: %s", lp)
		}
	}

	// 不能和其它证书夹的路径撞车：撞加载路径会污染别人的自动加载，
	// 撞导出路径会让两个证书夹互相覆盖，最终谁生效取决于执行顺序。
	if err = receiver.checkExportPathConflictWithOthers(selfId, certPath, keyPath); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// checkExportPathConflictWithOthers 检查导出路径是否和其它证书夹的加载/导出路径冲突。
func (receiver *WafSslConfigService) checkExportPathConflictWithOthers(selfId, certPath, keyPath string) error {
	var others []model.SslConfig
	if err := global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).
		Select("id", "domains", "cert_path", "key_path", "export_cert_path", "export_key_path").
		Find(&others).Error; err != nil {
		// 查不到就不拦，避免因为数据库抖动把用户的正常保存挡住
		zlog.Warn("SSLExport", fmt.Sprintf("检查导出路径冲突时查询失败: %v", err))
		return nil
	}
	for _, other := range others {
		if other.Id == selfId {
			continue
		}
		occupied := []struct{ path, usage string }{
			{other.CertPath, "自动加载证书路径"},
			{other.KeyPath, "自动加载密钥路径"},
			{other.ExportCertPath, "导出证书路径"},
			{other.ExportKeyPath, "导出密钥路径"},
		}
		for _, o := range occupied {
			op := strings.TrimSpace(o.path)
			if op == "" {
				continue
			}
			// 仅判是否撞车，IsSameFilePath 自带 Clean/大小写归一，无需再跑导出策略校验
			if utils.IsSameFilePath(op, certPath) || utils.IsSameFilePath(op, keyPath) {
				return fmt.Errorf("该路径已被证书夹[%s]的%s占用: %s", other.Domains, o.usage, op)
			}
		}
	}
	return nil
}

// saveExportStatus 只更新 export_status 一列，不动 UPDATE_TIME，避免干扰其它逻辑。
func (receiver *WafSslConfigService) saveExportStatus(id, status string) {
	status = fmt.Sprintf("%s %s", time.Now().Format("2006-01-02 15:04:05"), status)
	if len([]rune(status)) > 200 {
		status = string([]rune(status)[:200])
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).Where("id = ?", id).
		Update("export_status", status).Error; err != nil {
		zlog.Warn("SSLExport", fmt.Sprintf("证书夹[%s] 记录导出状态失败: %v", id, err))
	}
}
