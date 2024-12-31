package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/utils/ssl"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

var (
	wafSslOrderService  = waf_service.WafSSLOrderServiceApp
	wafHostService      = waf_service.WafHostServiceApp
	wafSslConfigService = waf_service.WafSslConfigServiceApp
)

// ApplySSLOrder 申请SSL证书处理
func (waf *WafEngine) ApplySSLOrder(chanType int, bean model.SslOrder) {
	if chanType == enums.ChanSslOrderSubmitted {
		//发起申请
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.RegistrationSSL(bean, filePath)
		if err == nil {
			zlog.Error("证书首次申请处理", err)
			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultCertificate = nil
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)
			} else {
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)
			}
		} else {
			//设置数据
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultCertificate = nil
			updateSSLOrder.ResultError = err.Error()
			err := wafSslOrderService.ModifyById(updateSSLOrder)
			if err != nil {
				zlog.Error("保存结果", err.Error())
			}
		}

	} else if chanType == enums.ChanSslOrderrenew {
		//发起申请
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.ReNewSSL(bean, filePath)
		if err == nil {
			zlog.Error("证书续期申请处理", err)
			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)
			} else {
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)
			}
		} else {
			//设置数据
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultError = err.Error()
			err := wafSslOrderService.ModifyById(updateSSLOrder)
			if err != nil {
				zlog.Error("续期保存结果", err.Error())
			}
		}
	}
}

func (waf *WafEngine) processSSL(updateSSLOrder model.SslOrder, bean model.SslOrder) error {
	err := wafSslOrderService.ModifyById(updateSSLOrder)
	if err != nil {
		return errors.New("更新SslOrder是失败")
	}
	newSslConfig := model.SslConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
	}
	err = newSslConfig.FillByCertAndKey(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey))
	if err != nil {
		return errors.New("填充证书夹失败")
	}

	//1. 查找关联主机是否绑定了证书信息， 如有有则生成新证书夹信息，否则  新增
	hostBean := wafHostService.GetDetailByCodeApi(bean.HostCode)
	if hostBean.BindSslId == "" {
		//添加到证书夹内
		wafSslConfigService.AddInner(newSslConfig)
		//1.更新主机信息 2.发送主机通知
		err = wafHostService.UpdateSSLInfoAndBindId(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey), bean.HostCode, newSslConfig.Id)
		if err == nil {
			hostBean.Keyfile = string(updateSSLOrder.ResultPrivateKey)
			hostBean.Certfile = string(updateSSLOrder.ResultCertificate)
			var chanInfo = spec.ChanCommonHost{
				HostCode:   bean.HostCode,
				Type:       enums.ChanTypeSSL,
				Content:    hostBean,
				OldContent: hostBean,
			}
			global.GWAF_CHAN_MSG <- chanInfo
		}
	} else {
		oldSslConfig := wafSslConfigService.GetDetailInner(hostBean.BindSslId)

		if newSslConfig.CompareSSLNeedUpdate(newSslConfig, oldSslConfig) {
			//将原来的证书备份，新证书更新到现有证书里面
			wafSslConfigService.AddInner(oldSslConfig)
			newSslConfig.Id = oldSslConfig.Id
			wafSslConfigService.ModifyInner(newSslConfig)
			//1.更新主机信息 2.发送主机通知
			err = wafHostService.UpdateSSLInfo(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey), bean.HostCode)
			if err == nil {
				hostBean.Keyfile = string(bean.ResultPrivateKey)
				hostBean.Certfile = string(bean.ResultCertificate)
				var chanInfo = spec.ChanCommonHost{
					HostCode:   bean.HostCode,
					Type:       enums.ChanTypeSSL,
					Content:    hostBean,
					OldContent: hostBean,
				}
				global.GWAF_CHAN_MSG <- chanInfo
			}
		}

	}
	return nil
}
