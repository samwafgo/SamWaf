package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/utils/ssl"
	"SamWaf/wafssl"
	"errors"
	"fmt"
	"time"
)

var (
	wafSslOrderService  = waf_service.WafSSLOrderServiceApp
	wafHostService      = waf_service.WafHostServiceApp
	wafSslConfigService = waf_service.WafSslConfigServiceApp
)

// ApplySSLOrder 申请SSL证书处理
func (waf *WafEngine) ApplySSLOrder(chanType int, bean model.SslOrder) {
	if bean.ApplyMethod == "dns01" {
		//加载环境变量
		privateGroupName := bean.PrivateGroupName
		privateGroupBelongCloud := bean.ApplyDns
		zlog.Debug(fmt.Sprintf("Loading DNS provider env info - Group: `%s`, Cloud: `%s` for domain: %s", privateGroupName, privateGroupBelongCloud, bean.ApplyDomain))
		//查询环境变量信息
		wafssl.LoadDnsProviderEnvInfo(privateGroupName, privateGroupBelongCloud)
	}
	eab_kid := ""
	eab_hmac_key := ""
	if bean.ApplyPlatform == "zerossl" {
		eab_kid = global.GCONFIG_ZEROSSL_EAB_KID
		eab_hmac_key = global.GCONFIG_ZEROSSL_EAB_HMAC_KEY
	}
	if chanType == enums.ChanSslOrderSubmitted {
		//发起申请
		zlog.Info(fmt.Sprintf("%s 正在进行首次证书申请", bean.ApplyDomain))
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.RegistrationSSL(bean, filePath, waf_service.GetCAServerAddress(bean.ApplyPlatform), bean.ApplyPlatform, eab_kid, eab_hmac_key)
		if err == nil {
			zlog.Info(fmt.Sprintf("%s 首次证书申请成功", bean.ApplyDomain))

			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				zlog.Error(fmt.Sprintf("%s 证书首次申请后续 失败 %v", bean.ApplyDomain, err.Error()))
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultCertificate = nil
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)

				// 发送SSL证书申请失败的系统日志和消息通知
				sslError := fmt.Sprintf("SSL证书申请失败 - 域名: %s, 错误: %v", bean.ApplyDomain, err.Error())
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "SSL证书申请",
					OpContent: sslError,
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

				serverName := global.GWAF_CUSTOM_SERVER_NAME
				if serverName == "" {
					serverName = "未命名服务器"
				}
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{
						OperaType: "SSL证书申请失败",
						Server:    serverName,
					},
					OperaCnt: sslError,
				})
			} else {
				zlog.Info(fmt.Sprintf("%s 证书首次申请后续 成功", bean.ApplyDomain))
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)

				// 发送SSL证书申请成功的系统日志和消息通知
				sslSuccess := fmt.Sprintf("SSL证书申请成功 - 域名: %s, 有效期至: %s", bean.ApplyDomain, time.Time(updateSSLOrder.ResultValidTo).Format("2006-01-02"))
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "SSL证书申请",
					OpContent: sslSuccess,
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

				serverName := global.GWAF_CUSTOM_SERVER_NAME
				if serverName == "" {
					serverName = "未命名服务器"
				}
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{
						OperaType: "SSL证书申请成功",
						Server:    serverName,
					},
					OperaCnt: sslSuccess,
				})
			}
		} else {
			//设置数据
			zlog.Error(fmt.Sprintf("%s 首次证书申请 失败 %v", bean.ApplyDomain, err.Error()))
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultCertificate = nil
			updateSSLOrder.ResultError = err.Error()
			wafSslOrderService.ModifyById(updateSSLOrder)

			// 发送SSL证书申请失败的系统日志和消息通知
			sslError := fmt.Sprintf("SSL证书申请失败 - 域名: %s, 错误: %v", bean.ApplyDomain, err.Error())
			wafSysLog := model.WafSysLog{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				OpType:    "SSL证书申请",
				OpContent: sslError,
			}
			global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

			serverName := global.GWAF_CUSTOM_SERVER_NAME
			if serverName == "" {
				serverName = "未命名服务器"
			}
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{
					OperaType: "SSL证书申请失败",
					Server:    serverName,
				},
				OperaCnt: sslError,
			})
		}

	} else if chanType == enums.ChanSslOrderrenew {
		//发起申请
		zlog.Info(fmt.Sprintf("%s 正在证书续期申请处理", bean.ApplyDomain))
		filePath := utils.GetCurrentDir() + "/data/vhost/" + bean.HostCode
		filePathErr := utils.CheckPathAndCreate(filePath)
		if filePathErr != nil {
			zlog.Error("ApplySSLOrder", filePathErr.Error())
		}
		updateSSLOrder, err := ssl.ReNewSSL(bean, filePath, waf_service.GetCAServerAddress(bean.ApplyPlatform), bean.ApplyPlatform, eab_kid, eab_hmac_key)
		if err == nil {
			zlog.Info(fmt.Sprintf("%s 证书续期申请成功", bean.ApplyDomain))

			err := waf.processSSL(updateSSLOrder, bean)
			if err != nil {
				zlog.Error(fmt.Sprintf("%s 证书续期申请处理后续 失败 %v", bean.ApplyDomain, err.Error()))
				updateSSLOrder.ApplyStatus = "fail"
				updateSSLOrder.ResultError = err.Error()
				wafSslOrderService.ModifyById(updateSSLOrder)

				// 发送SSL证书续期失败的系统日志和消息通知
				sslError := fmt.Sprintf("SSL证书续期失败 - 域名: %s, 错误: %v", bean.ApplyDomain, err.Error())
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "SSL证书续期",
					OpContent: sslError,
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

				serverName := global.GWAF_CUSTOM_SERVER_NAME
				if serverName == "" {
					serverName = "未命名服务器"
				}
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{
						OperaType: "SSL证书续期失败",
						Server:    serverName,
					},
					OperaCnt: sslError,
				})
			} else {
				zlog.Info(fmt.Sprintf("%s 证书续期处理后续 成功", bean.ApplyDomain))
				updateSSLOrder.ApplyStatus = "success"
				updateSSLOrder.ResultError = ""
				wafSslOrderService.ModifyById(updateSSLOrder)

				// 发送SSL证书续期成功的系统日志和消息通知
				sslSuccess := fmt.Sprintf("SSL证书续期成功 - 域名: %s, 有效期至: %s", bean.ApplyDomain, time.Time(updateSSLOrder.ResultValidTo).Format("2006-01-02"))
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "SSL证书续期",
					OpContent: sslSuccess,
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

				serverName := global.GWAF_CUSTOM_SERVER_NAME
				if serverName == "" {
					serverName = "未命名服务器"
				}
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{
						OperaType: "SSL证书续期成功",
						Server:    serverName,
					},
					OperaCnt: sslSuccess,
				})
			}
		} else {
			//设置数据
			zlog.Error(fmt.Sprintf("%s 续期证书申请 失败 %v", bean.ApplyDomain, err.Error()))
			updateSSLOrder.ApplyStatus = "fail"
			updateSSLOrder.ResultError = err.Error()
			wafSslOrderService.ModifyById(updateSSLOrder)

			// 发送SSL证书续期失败的系统日志和消息通知
			sslError := fmt.Sprintf("SSL证书续期失败 - 域名: %s, 错误: %v", bean.ApplyDomain, err.Error())
			wafSysLog := model.WafSysLog{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				OpType:    "SSL证书续期",
				OpContent: sslError,
			}
			global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

			serverName := global.GWAF_CUSTOM_SERVER_NAME
			if serverName == "" {
				serverName = "未命名服务器"
			}
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{
					OperaType: "SSL证书续期失败",
					Server:    serverName,
				},
				OperaCnt: sslError,
			})
		}
	}
}

// exportSslConfigFile 证书夹内容更新后，把证书同步导出成实体文件（issue #929）。
//
// 导出是附加动作：未配置导出路径就静默跳过；配置了但路径不合法、目录没权限、文件被占用，
// 一律只记录日志和系统日志，绝不影响证书申请/续期本身的成败判定。
// 之所以在这里额外发一条通知：续期是低频事件（一张证书 60 天一次），静默失败的话
// 用户要等到外部程序拿着过期证书报错才会发现。
func exportSslConfigFile(sslConfigId string, domain string, scene string) {
	msg, err := wafSslConfigService.ExportById(sslConfigId)
	if err != nil {
		exportErrMsg := fmt.Sprintf("SSL证书导出失败 - 域名: %s, 场景: %s, 错误: %v", domain, scene, err.Error())
		zlog.Error(exportErrMsg)

		wafSysLog := model.WafSysLog{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			OpType:    "SSL证书导出",
			OpContent: exportErrMsg,
		}
		global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

		serverName := global.GWAF_CUSTOM_SERVER_NAME
		if serverName == "" {
			serverName = "未命名服务器"
		}
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{
				OperaType: "SSL证书导出失败",
				Server:    serverName,
			},
			OperaCnt: exportErrMsg,
		})
		return
	}
	if msg != "" {
		zlog.Info(fmt.Sprintf("%s 证书导出 %s", domain, msg))
	}
}

func (waf *WafEngine) processSSL(updateSSLOrder model.SslOrder, bean model.SslOrder) error {
	newSslConfig := model.SslConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
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
		//该证书夹由 SamWaf 自动申请管理，关闭路径自动加载，避免凌晨3点被本地旧文件覆盖
		newSslConfig.AutoLoadPath = 0
		//添加到证书夹内
		wafSslConfigService.CreateInner(newSslConfig)
		//这里不触发证书导出：新建的证书夹条目导出路径必然为空（用户还没机会配置），
		//而且 CreateInner 遇到重复序列号会直接返回不落库，此时按ID导出反而会误报"证书夹不存在"。
		//用户在证书夹页面配好导出路径后，保存那一下会立刻导出，之后每次续期也会导出。
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
			wafSslConfigService.CreateNewIdInner(oldSslConfig)
			newSslConfig.Id = oldSslConfig.Id
			//该证书夹由 SamWaf 自动申请管理，关闭路径自动加载，避免凌晨3点被本地旧文件覆盖
			newSslConfig.AutoLoadPath = 0
			//把最新的配置上去
			wafSslConfigService.ModifyInner(newSslConfig)

			//证书导出(落盘)：申请/续期成功后把新证书同步成实体文件，供 nginx 等外部程序使用
			exportSslConfigFile(newSslConfig.Id, bean.ApplyDomain, "证书申请/续期")

			//若管理端证书绑定了该证书夹条目，顺带刷新管理端证书
			waf_service.RefreshManagerCertBySslConfig(newSslConfig.Id, newSslConfig.CertContent, newSslConfig.KeyContent)

			//获取所有绑定了相同证书夹的主机
			relatedHosts := wafHostService.GetHostBySSLConfigId(newSslConfig.Id)
			zlog.Info(fmt.Sprintf("%s 找到 %d 个使用相同证书夹的主机", bean.ApplyDomain, len(relatedHosts)))

			//更新所有关联主机的证书信息并发送通知
			for _, host := range relatedHosts {
				//更新主机的证书信息
				err = wafHostService.UpdateSSLInfo(string(updateSSLOrder.ResultCertificate), string(updateSSLOrder.ResultPrivateKey), host.Code)
				if err != nil {
					zlog.Error(fmt.Sprintf("更新主机 %s(%s) 证书信息失败: %v", host.Host, host.Code, err))
					continue
				}

				//重新查询主机信息，确保获取最新数据
				updatedHost := wafHostService.GetDetailByCodeApi(host.Code)
				if updatedHost.Code == "" {
					zlog.Error(fmt.Sprintf("无法获取更新后的主机信息: %s", host.Code))
					continue
				}

				//发送主机通知，触发证书重新加载
				var chanInfo = spec.ChanCommonHost{
					HostCode:   updatedHost.Code,
					Type:       enums.ChanTypeSSL,
					Content:    updatedHost,
					OldContent: host,
				}
				global.GWAF_CHAN_MSG <- chanInfo
				zlog.Info(fmt.Sprintf("成功更新主机 %s(%s) 的证书信息", updatedHost.Host, updatedHost.Code))
			}
		} else {
			zlog.Info(fmt.Sprintf("%s 当前主机已绑定的证书和新证书相比后不允许更新", bean.ApplyDomain))
		}

	}
	return nil
}
