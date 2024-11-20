package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/utils"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/satori/go.uuid"
	"gorm.io/gorm"
	"path/filepath"
	"time"
)

type WafSslConfigService struct{}

var WafSslConfigServiceApp = new(WafSslConfigService)

func (receiver *WafSslConfigService) AddApi(req request.SslConfigAddReq) error {
	block, _ := pem.Decode([]byte(req.CertContent))
	if block == nil {
		return errors.New("无法解码PEM数据")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("解析证书失败")
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
	} else {
		domains = "未指定域名"
	}
	err = receiver.CheckIsExistApi(serialNo)
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.New("证书已存在")
	}
	var bean = &model.SslConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
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
		ValidFrom:   validFrom,
		ValidTo:     validTo,
		Domains:     domains,
		CertPath:    req.CertPath,
		KeyPath:     req.KeyPath,
	}
	if bean.CertPath == "" {
		bean.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.crt")
	}
	if bean.KeyPath == "" {
		bean.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", bean.Id, "domain.key")
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSslConfigService) AddInner(config model.SslConfig) {
	//检测如果证书编号已经存在不需在进行添加了
	err := global.GWAF_LOCAL_DB.First(&model.SslConfig{}, "serial_no = ?", config.SerialNo).Error
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		zlog.Info("证书已经存在不进行再次备份")
		return
	}
	config.Id = uuid.NewV4().String()
	if config.CertPath == "" {
		config.CertPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.crt")
	}
	if config.KeyPath == "" {
		config.KeyPath = filepath.Join(utils.GetCurrentDir(), "ssl", config.Id, "domain.key")
	}
	global.GWAF_LOCAL_DB.Create(config)
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
	} else {
		domains = "未指定域名"
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
		"ValidFrom":   validFrom,
		"ValidTo":     validTo,
		"Domains":     domains,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
		"CertPath":    req.CertPath,
		"KeyPath":     req.KeyPath,
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
		"CertContent": config.CertContent,
		"KeyContent":  config.KeyContent,
		"SerialNo":    config.SerialNo,
		"Subject":     config.Subject,
		"Issuer":      config.Issuer,
		"ValidFrom":   config.ValidFrom,
		"ValidTo":     config.ValidTo,
		"Domains":     config.Domains,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
		"CertPath":    config.CertPath,
		"KeyPath":     config.KeyPath,
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
	rep := response.WafSslConfigRep{
		SslConfig:      bean,
		ExpirationInfo: bean.ExpirationMessage(),
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
		rep := response.WafSslConfigRep{
			SslConfig:      sslConfig,
			ExpirationInfo: sslConfig.ExpirationMessage(),
		}
		repList = append(repList, rep)
	}

	return repList, total, nil
}

func (receiver *WafSslConfigService) GetAllListInner() ([]response.WafSslConfigRep, int64, error) {
	var list []model.SslConfig
	var total int64 = 0
	var whereField = ""
	var whereValues []interface{}

	global.GWAF_LOCAL_DB.Model(&model.SslConfig{}).Where(whereField, whereValues...).Order("valid_to desc").Find(&list)
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
		rep := response.WafSslConfigRep{
			SslConfig:      sslConfig,
			ExpirationInfo: sslConfig.ExpirationMessage(),
		}
		repList = append(repList, rep)
	}

	return repList, total, nil
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
