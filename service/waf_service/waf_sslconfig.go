package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"path/filepath"
	"strings"
	"time"
)

type WafSslConfigService struct{}

var WafSslConfigServiceApp = new(WafSslConfigService)

// validateCertKeyPair 校验 key_content 为合法私钥且与证书配对。
// 安全加固(EXT-2026-0821-01)：SSL 导出功能会把 key_content 原样落盘到用户指定路径，
// 若不校验，任意文本即可经导出写入宿主机任意文件。要求私钥合法且与证书匹配后，
// 落盘内容被约束为合法 PEM 证书/私钥，无法再被构造成 authorized_keys/cron 等可执行载荷。
// 私钥为空(严格等于"")时跳过：与导出侧的空值判断(config.KeyContent == "")保持一致，
// 不改变"仅存证书不导出"的既有用法。注意必须用严格 ==""，不能 TrimSpace：
// 否则纯空白私钥会跳过本校验，却因导出侧判定为非空而被原样落盘，形成绕过。
func validateCertKeyPair(certContent, keyContent string) error {
	if keyContent == "" {
		return nil
	}
	if _, err := tls.X509KeyPair([]byte(certContent), []byte(keyContent)); err != nil {
		return errors.New("私钥格式非法或与证书不匹配")
	}
	return nil
}

// AddApi 新增证书夹，返回新记录的ID（供调用方触发证书导出）
func (receiver *WafSslConfigService) AddApi(req request.SslConfigAddReq) (string, error) {
	block, _ := pem.Decode([]byte(req.CertContent))
	if block == nil {
		return "", errors.New("无法解码PEM数据")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", errors.New("解析证书失败")
	}

	// 安全加固：私钥必须合法且与证书配对，防止任意文本经导出功能写入宿主机
	if err = validateCertKeyPair(req.CertContent, req.KeyContent); err != nil {
		return "", err
	}

	serialNo := cert.SerialNumber.String()
	subject := cert.Subject.String()
	issuer := cert.Issuer.String()
	validFrom := cert.NotBefore
	validTo := cert.NotAfter

	domains := ""
	if len(cert.DNSNames) > 0 {
		for _, domain := range cert.DNSNames {
			if domains != "" {
				domains += ", "
			}
			domains += domain
		}
	}
	// 检查是否有IP地址
	if len(cert.IPAddresses) > 0 {
		for _, ip := range cert.IPAddresses {
			if domains != "" {
				domains += ", "
			}
			domains += ip.String()
		}
	}
	// 如果既没有域名也没有IP
	if domains == "" {
		domains = "未指定域名或IP"
	}
	err = receiver.CheckIsExistApi(serialNo)
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", errors.New("证书已存在")
	}
	var bean = &model.SslConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		CertContent: req.CertContent,
		KeyContent:  req.KeyContent,
		SerialNo:    serialNo,
		Subject:     subject,
		Issuer:      issuer,
		ValidFrom:   customtype.JsonTime(validFrom),
		ValidTo:     customtype.JsonTime(validTo),
		Domains:     domains,
		CertPath:    req.CertPath,
		KeyPath:     req.KeyPath,
		//证书导出路径：留空即不导出，此处只做去空格，合法性在真正导出时校验，
		//避免因为导出路径写错就把证书本身的保存挡下来
		ExportCertPath: strings.TrimSpace(req.ExportCertPath),
		ExportKeyPath:  strings.TrimSpace(req.ExportKeyPath),
	}
	//路径自动加载开关：未提供时默认开启(1)
	if req.AutoLoadPath != nil {
		bean.AutoLoadPath = *req.AutoLoadPath
	} else {
		bean.AutoLoadPath = 1
	}
	if bean.CertPath == "" {
		bean.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.crt")
	}
	if bean.KeyPath == "" {
		bean.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.key")
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return bean.Id, nil
}

func (receiver *WafSslConfigService) CreateNewIdInner(config model.SslConfig) {
	//检测如果证书编号已经存在不需在进行添加了
	err := global.GWAF_LOCAL_DB.First(&model.SslConfig{}, "serial_no = ?", config.SerialNo).Error
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		zlog.Info(fmt.Sprintf("%s 证书已经存在不进行再次备份", config.Domains))
		return
	}
	config.Id = uuid.GenUUID()
	//备份条目不继承导出配置：否则以后编辑这条备份会把旧证书写回导出路径，覆盖掉新证书
	config.ExportCertPath = ""
	config.ExportKeyPath = ""
	config.ExportStatus = ""
	if config.CertPath == "" {
		config.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.crt")
	}
	if config.KeyPath == "" {
		config.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.key")
	}
	//必须传指针：按值传给 Create 会导致 GORM 回写字段默认值时对不可寻址反射值 SetInt 而 panic
	global.GWAF_LOCAL_DB.Create(&config)
	zlog.Info(fmt.Sprintf("%s 原来证书已备份", config.Domains))
}
func (receiver *WafSslConfigService) CreateInner(config model.SslConfig) {
	//检测如果证书编号已经存在不需在进行添加了
	err := global.GWAF_LOCAL_DB.First(&model.SslConfig{}, "serial_no = ?", config.SerialNo).Error
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		zlog.Info(fmt.Sprintf("%s 证书已经存在不进行再次备份", config.Domains))
		return
	}
	if config.CertPath == "" {
		config.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.crt")
	}
	if config.KeyPath == "" {
		config.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.key")
	}
	//必须传指针：按值传给 Create 会导致 GORM 回写字段默认值时对不可寻址反射值 SetInt 而 panic
	global.GWAF_LOCAL_DB.Create(&config)
	zlog.Info(fmt.Sprintf("%s 原来证书已备份", config.Domains))
}

func (receiver *WafSslConfigService) CheckIsExistApi(serialNo string) error {
	return global.GWAF_LOCAL_DB.First(&model.SslConfig{}, "serial_no = ?", serialNo).Error
}

func (receiver *WafSslConfigService) ModifyApi(req request.SslConfigEditReq) error {
	block, _ := pem.Decode([]byte(req.CertContent))
	if block == nil {
		return errors.New("无法解码PEM数据")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("解析证书失败")
	}

	// 安全加固：私钥必须合法且与证书配对，防止任意文本经导出功能写入宿主机
	if err = validateCertKeyPair(req.CertContent, req.KeyContent); err != nil {
		return err
	}

	serialNo := cert.SerialNumber.String()
	subject := cert.Subject.String()
	issuer := cert.Issuer.String()
	validFrom := cert.NotBefore
	validTo := cert.NotAfter

	domains := ""
	if len(cert.DNSNames) > 0 {
		for _, domain := range cert.DNSNames {
			if domains != "" {
				domains += ", "
			}
			domains += domain
		}
	}
	// 检查是否有IP地址
	if len(cert.IPAddresses) > 0 {
		for _, ip := range cert.IPAddresses {
			if domains != "" {
				domains += ", "
			}
			domains += ip.String()
		}
	}
	// 如果既没有域名也没有IP
	if domains == "" {
		domains = "未指定域名或IP"
	}

	var bean model.SslConfig
	global.GWAF_LOCAL_DB.Where("serial_no = ?", serialNo).Find(&bean)
	if bean.Id != "" && bean.SerialNo != serialNo {
		return errors.New("该证书已经存在")
	}

	if req.CertPath == "" {
		req.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.crt")
	}
	if req.KeyPath == "" {
		req.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.key")
	}
	beanMap := map[string]interface{}{
		"CertContent": req.CertContent,
		"KeyContent":  req.KeyContent,
		"SerialNo":    serialNo,
		"Subject":     subject,
		"Issuer":      issuer,
		"ValidFrom":   customtype.JsonTime(validFrom),
		"ValidTo":     customtype.JsonTime(validTo),
		"Domains":     domains,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
		"CertPath":    req.CertPath,
		"KeyPath":     req.KeyPath,
	}
	//仅当请求提供了路径自动加载开关时才更新该列，避免旧前端不传该字段导致被误置0
	if req.AutoLoadPath != nil {
		beanMap["AutoLoadPath"] = *req.AutoLoadPath
	}
	//同理，导出路径只在前端明确传了才更新，nil=旧前端不认识该字段，保持库里原值
	if req.ExportCertPath != nil {
		beanMap["ExportCertPath"] = strings.TrimSpace(*req.ExportCertPath)
	}
	if req.ExportKeyPath != nil {
		beanMap["ExportKeyPath"] = strings.TrimSpace(*req.ExportKeyPath)
	}
	err = global.GWAF_LOCAL_DB.Model(model.SslConfig{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}

func (receiver *WafSslConfigService) ModifyInner(config model.SslConfig) error {
	if config.CertPath == "" {
		config.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.crt")
	}
	if config.KeyPath == "" {
		config.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.key")
	}
	beanMap := map[string]interface{}{
		"CertContent":  config.CertContent,
		"KeyContent":   config.KeyContent,
		"SerialNo":     config.SerialNo,
		"Subject":      config.Subject,
		"Issuer":       config.Issuer,
		"ValidFrom":    config.ValidFrom,
		"ValidTo":      config.ValidTo,
		"Domains":      config.Domains,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
		"CertPath":     config.CertPath,
		"KeyPath":      config.KeyPath,
		"AutoLoadPath": config.AutoLoadPath,
	}
	err := global.GWAF_LOCAL_DB.Model(model.SslConfig{}).Where("id = ?", config.Id).Updates(beanMap).Error
	return err
}

// GetDetailApi gets the SSL configuration details by its ID
func (receiver *WafSslConfigService) GetDetailApi(req request.SslConfigDetailReq) response.WafSslConfigRep {
	var bean model.SslConfig
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	if bean.CertPath == "" {
		bean.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.crt")
	}
	if bean.KeyPath == "" {
		bean.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.key")
	}

	// 查询绑定的主机并格式化显示
	bindHosts := receiver.formatBindHosts(bean.Id)

	rep := response.WafSslConfigRep{
		SslConfig:      bean,
		ExpirationInfo: bean.ExpirationMessage(),
		BindHosts:      bindHosts,
	}
	return rep
}

// GetDetailInner 获取详情信息
func (receiver *WafSslConfigService) GetDetailInner(id string) model.SslConfig {
	var bean model.SslConfig
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafSslConfigService) GetListApi(req request.SslConfigSearchReq) ([]response.WafSslConfigRep, int64, error) {
	var list []model.SslConfig
	var total int64 = 0
	var whereField = ""
	var whereValues []interface{}

	if len(req.Domains) > 0 {
		whereField += "domains like ?"
		whereValues = append(whereValues, "%"+req.Domains+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order("valid_to desc").Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).Where(whereField, whereValues...).Count(&total)

	// 初始化返回结果列表
	var repList []response.WafSslConfigRep

	// 遍历查询结果，构建返回数据
	for _, sslConfig := range list {
		if sslConfig.CertPath == "" {
			sslConfig.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", sslConfig.Id, "domain.crt")
		}
		if sslConfig.KeyPath == "" {
			sslConfig.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", sslConfig.Id, "domain.key")
		}

		// 查询绑定的主机并格式化显示
		bindHosts := receiver.formatBindHosts(sslConfig.Id)

		rep := response.WafSslConfigRep{
			SslConfig:      sslConfig,
			ExpirationInfo: sslConfig.ExpirationMessage(),
			BindHosts:      bindHosts,
		}
		repList = append(repList, rep)
	}

	return repList, total, nil
}

func (receiver *WafSslConfigService) GetAllListInner() ([]response.WafSslConfigRep, error) {
	var list []model.SslConfig

	var bindSslIDs []string
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Select("bind_ssl_id").Where(dialect.Q("ssl")+" = ? and bind_ssl_id <> ?", 1, "").Find(&bindSslIDs)

	global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).Where("id IN ?", bindSslIDs).Order("valid_to desc").Find(&list)

	// 初始化返回结果列表
	var repList []response.WafSslConfigRep

	// 遍历查询结果，构建返回数据
	for _, sslConfig := range list {
		if sslConfig.CertPath == "" {
			sslConfig.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", sslConfig.Id, "domain.crt")
		}
		if sslConfig.KeyPath == "" {
			sslConfig.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", sslConfig.Id, "domain.key")
		}
		rep := response.WafSslConfigRep{
			SslConfig:      sslConfig,
			ExpirationInfo: sslConfig.ExpirationMessage(),
		}
		repList = append(repList, rep)
	}

	return repList, nil
}

func (receiver *WafSslConfigService) DelApi(req request.SslConfigDeleteReq) error {
	var bean model.SslConfig
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.SslConfig{}).Error
	return err
}

// formatBindHosts 格式化绑定的主机列表
func (receiver *WafSslConfigService) formatBindHosts(sslId string) []string {
	var hosts []model.Hosts
	var result []string

	// 查询绑定该SSL的所有主机
	global.GWAF_LOCAL_DB.Where("bind_ssl_id = ?", sslId).Find(&hosts)

	// 格式化每个主机的显示信息
	for _, host := range hosts {
		var hostDisplay string

		// 构建括号内的内容
		var bracketContent []string

		// 如果是SSL，添加SSL标识
		if host.Ssl == 1 {
			bracketContent = append(bracketContent, "SSL")
		}

		// 如果有备注，添加备注
		if host.REMARKS != "" {
			bracketContent = append(bracketContent, host.REMARKS)
		}

		// 构建最终的Host显示字符串
		if len(bracketContent) > 0 {
			hostDisplay = fmt.Sprintf("%s:%d(%s)", host.Host, host.Port, strings.Join(bracketContent, ","))
		} else {
			hostDisplay = fmt.Sprintf("%s:%d", host.Host, host.Port)
		}

		result = append(result, hostDisplay)
	}

	return result
}
