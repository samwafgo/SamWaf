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
	"fmt"
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
		zlog.Info(fmt.Sprintf("%s 正在进行首次证书申请", bean.ApplyDomain))
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.RegistrationSSL(bean, filePath)
		if err == nil {
			zlog.Info(fmt.Sprintf("%s 首次证书申请成功", bean.ApplyDomain))

			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				zlog.Error(fmt.Sprintf("%s 证书首次申请后续 失败 %v", bean.ApplyDomain, err.Error()))
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultCertificate = nil
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)
			} else {
				zlog.Info(fmt.Sprintf("%s 证书首次申请后续 成功", bean.ApplyDomain))
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)
			}
		} else {
			//设置数据
			zlog.Error(fmt.Sprintf("%s 首次证书申请 失败 %v", bean.ApplyDomain, err.Error()))
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultCertificate = nil
			updateSSLOrder.ResultError = err.Error()
			wafSslOrderService.ModifyById(updateSSLOrder)
		}

	} else if chanType == enums.ChanSslOrderrenew {
		//发起申请
		zlog.Info(fmt.Sprintf("%s 正在证书续期申请处理", bean.ApplyDomain))
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.ReNewSSL(bean, filePath)
		if err == nil {
			zlog.Info(fmt.Sprintf("%s 证书续期申请成功", bean.ApplyDomain))

			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				zlog.Error(fmt.Sprintf("%s 证书续期申请处理后续 失败 %v", bean.ApplyDomain, err.Error()))
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)
			} else {
				zlog.Info(fmt.Sprintf("%s 证书续期处理后续 成功", bean.ApplyDomain))
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)
			}
		} else {
			//设置数据
			zlog.Error(fmt.Sprintf("%s 续期证书申请 失败 %v", bean.ApplyDomain, err.Error()))
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultError = err.Error()
			wafSslOrderService.ModifyById(updateSSLOrder)
		}
	}
}

func (waf *WafEngine) processSSL(updateSSLOrder model.SslOrder, bean model.SslOrder) error {
	newSslConfig := model.SslConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
	}
	err := newSslConfig.FillByCertAndKey(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey))
	if err != nil {
		return errors.New("填充证书夹失败")
	}

	//1. 查找关联主机是否绑定了证书信息， 如有有则生成新证书夹信息，否则  新增
	hostBean := wafHostService.GetDetailByCodeApi(bean.HostCode)
	oldSslConfig := wafSslConfigService.GetDetailInner(hostBean.BindSslId)
	//如果绑定为空 ，或者绑定的数据没有对应的数据就生产一个新的到证书夹里面
	if hostBean.BindSslId == "" || oldSslConfig.SerialNo == "" {
		zlog.Info(fmt.Sprintf("%s 当前主机未配置证书新增一个证书文件夹", bean.ApplyDomain))
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
		zlog.Info(fmt.Sprintf("%s 当前主机已配置证书文件夹绑定关系", bean.ApplyDomain))
		if newSslConfig.CompareSSLNeedUpdate(newSslConfig, oldSslConfig) {
			//将原来的证书备份，新证书更新到现有证书里面
			zlog.Info(fmt.Sprintf("%s 当前主机已绑定的证书和新证书相比后允许更新", bean.ApplyDomain))
			//备份原来的配置
			wafSslConfigService.AddInner(oldSslConfig)
			newSslConfig.Id = oldSslConfig.Id
			//把最新的配置上去
			wafSslConfigService.ModifyInner(newSslConfig)
			//1.更新主机信息 2.发送主机通知
			err = wafHostService.UpdateSSLInfo(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey), bean.HostCode)
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
			zlog.Info(fmt.Sprintf("%s 当前主机已绑定的证书和新证书相比后不允许更新", bean.ApplyDomain))
		}

	}
	return nil
}
