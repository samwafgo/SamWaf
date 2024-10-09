package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/satori/go.uuid"
	"gorm.io/gorm"
	"time"
)

type WafSslConfigService struct{}

var SslConfigServiceApp = new(WafSslConfigService)

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
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
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
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
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
	}
	err = global.GWAF_LOCAL_DB.Model(model.SslConfig{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}

// GetDetailApi gets the SSL configuration details by its ID
func (receiver *WafSslConfigService) GetDetailApi(req request.SslConfigDetailReq) model.SslConfig {
	var bean model.SslConfig
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

func (receiver *WafSslConfigService) GetListApi(req request.SslConfigSearchReq) ([]model.SslConfig, int64, error) {
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

	return list, total, nil
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
