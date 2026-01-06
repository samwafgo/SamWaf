package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/validfield"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type WafHostService struct{}

var WafHostServiceApp = new(WafHostService)

func (receiver *WafHostService) AddApi(wafHostAddReq request.WafHostAddReq) (string, error) {
	uniCode := ""
	if wafHostAddReq.Code == "" {
		uniCode = uuid.GenUUID()
	} else {
		uniCode = wafHostAddReq.Code
	}

	// 如果没有设置HTTP认证路径前缀，则生成随机前缀
	httpAuthPathPrefix := wafHostAddReq.HttpAuthPathPrefix
	if httpAuthPathPrefix == "" {
		httpAuthPathPrefix = utils.GenerateRandomPathPrefix()
	}

	// 处理验证码配置JSON，如果没有设置路径前缀，则生成随机前缀
	captchaJSON := wafHostAddReq.CaptchaJSON
	if captchaJSON != "" {
		var captchaConfig model.CaptchaConfig
		err := json.Unmarshal([]byte(captchaJSON), &captchaConfig)
		if err == nil && captchaConfig.PathPrefix == "" {
			captchaConfig.PathPrefix = utils.GenerateRandomPathPrefix()
			// 重新序列化
			updatedJSON, err := json.Marshal(captchaConfig)
			if err == nil {
				captchaJSON = string(updatedJSON)
			}
		}
	}

	var wafHost = &model.Hosts{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Code:                 uniCode,
		Host:                 wafHostAddReq.Host,
		Port:                 wafHostAddReq.Port,
		Ssl:                  wafHostAddReq.Ssl,
		GUARD_STATUS:         1,
		REMOTE_SYSTEM:        wafHostAddReq.REMOTE_SYSTEM,
		REMOTE_APP:           wafHostAddReq.REMOTE_APP,
		Remote_host:          wafHostAddReq.Remote_host,
		Remote_port:          wafHostAddReq.Remote_port,
		Remote_ip:            wafHostAddReq.Remote_ip,
		Certfile:             wafHostAddReq.Certfile,
		Keyfile:              wafHostAddReq.Keyfile,
		REMARKS:              wafHostAddReq.REMARKS,
		GLOBAL_HOST:          0,
		DEFENSE_JSON:         wafHostAddReq.DEFENSE_JSON,
		START_STATUS:         wafHostAddReq.START_STATUS,
		EXCLUDE_URL_LOG:      wafHostAddReq.EXCLUDE_URL_LOG,
		IsEnableLoadBalance:  wafHostAddReq.IsEnableLoadBalance,
		LoadBalanceStage:     wafHostAddReq.LoadBalanceStage,
		UnrestrictedPort:     wafHostAddReq.UnrestrictedPort,
		BindSslId:            wafHostAddReq.BindSslId,
		AutoJumpHTTPS:        wafHostAddReq.AutoJumpHTTPS,
		BindMoreHost:         wafHostAddReq.BindMoreHost,
		IsTransBackDomain:    wafHostAddReq.IsTransBackDomain,
		BindMorePort:         wafHostAddReq.BindMorePort,
		IsEnableHttpAuthBase: wafHostAddReq.IsEnableHttpAuthBase,
		HttpAuthBaseType:     wafHostAddReq.HttpAuthBaseType,
		HttpAuthPathPrefix:   httpAuthPathPrefix,
		ResponseTimeOut:      wafHostAddReq.ResponseTimeOut,
		HealthyJSON:          wafHostAddReq.HealthyJSON,
		InsecureSkipVerify:   wafHostAddReq.InsecureSkipVerify,
		CaptchaJSON:          captchaJSON,
		AntiLeechJSON:        wafHostAddReq.AntiLeechJSON,
		CacheJSON:            wafHostAddReq.CacheJSON,
		StaticSiteJSON:       wafHostAddReq.StaticSiteJSON,
		DefaultEncoding:      wafHostAddReq.DefaultEncoding,
		LogOnlyMode:          wafHostAddReq.LogOnlyMode,
		TransportJSON:        wafHostAddReq.TransportJSON,
		CustomHeadersJSON:    wafHostAddReq.CustomHeadersJSON,
	}
	global.GWAF_LOCAL_DB.Create(wafHost)
	return wafHost.Code, nil
}

func (receiver *WafHostService) CheckIsExistApi(wafHostAddReq request.WafHostAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", wafHostAddReq.Host, wafHostAddReq.Port).Error
}
func (receiver *WafHostService) CheckIsExist(host string, port string) error {
	return global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", host, port).Error
}

func (receiver *WafHostService) ModifyApi(wafHostEditReq request.WafHostEditReq) error {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("host = ? and port= ?", wafHostEditReq.Host, wafHostEditReq.Port).Find(&webHost)
	if webHost.Id != "" && webHost.Code != wafHostEditReq.CODE {
		return errors.New("当前网站和端口已经存在")
	}
	if webHost.GLOBAL_HOST == 1 {
		return errors.New("全局网站不允许单独编辑")
	}
	hostMap := map[string]interface{}{
		"Host": wafHostEditReq.Host,
		"Port": wafHostEditReq.Port,
		"Ssl":  wafHostEditReq.Ssl,
		//"GUARD_STATUS":  0,
		"REMOTE_SYSTEM":        wafHostEditReq.REMOTE_SYSTEM,
		"REMOTE_APP":           wafHostEditReq.REMOTE_APP,
		"Remote_host":          wafHostEditReq.Remote_host,
		"Remote_ip":            wafHostEditReq.Remote_ip,
		"Remote_port":          wafHostEditReq.Remote_port,
		"REMARKS":              wafHostEditReq.REMARKS,
		"GLOBAL_HOST":          0,
		"Certfile":             wafHostEditReq.Certfile,
		"Keyfile":              wafHostEditReq.Keyfile,
		"UPDATE_TIME":          customtype.JsonTime(time.Now()),
		"DEFENSE_JSON":         wafHostEditReq.DEFENSE_JSON,
		"START_STATUS":         wafHostEditReq.START_STATUS,
		"EXCLUDE_URL_LOG":      wafHostEditReq.EXCLUDE_URL_LOG,
		"IsEnableLoadBalance":  wafHostEditReq.IsEnableLoadBalance,
		"LoadBalanceStage":     wafHostEditReq.LoadBalanceStage,
		"UnrestrictedPort":     wafHostEditReq.UnrestrictedPort,
		"BindSslId":            wafHostEditReq.BindSslId,
		"AutoJumpHTTPS":        wafHostEditReq.AutoJumpHTTPS,
		"BindMoreHost":         wafHostEditReq.BindMoreHost,
		"IsTransBackDomain":    wafHostEditReq.IsTransBackDomain,
		"BindMorePort":         wafHostEditReq.BindMorePort,
		"IsEnableHttpAuthBase": wafHostEditReq.IsEnableHttpAuthBase,
		"HttpAuthBaseType":     wafHostEditReq.HttpAuthBaseType,
		"HttpAuthPathPrefix":   wafHostEditReq.HttpAuthPathPrefix,
		"ResponseTimeOut":      wafHostEditReq.ResponseTimeOut,
		"HealthyJSON":          wafHostEditReq.HealthyJSON,
		"InsecureSkipVerify":   wafHostEditReq.InsecureSkipVerify,
		"CaptchaJSON":          wafHostEditReq.CaptchaJSON,
		"AntiLeechJSON":        wafHostEditReq.AntiLeechJSON,
		"CacheJSON":            wafHostEditReq.CacheJSON,
		"StaticSiteJSON":       wafHostEditReq.StaticSiteJSON,
		"DefaultEncoding":      wafHostEditReq.DefaultEncoding,
		"LogOnlyMode":          wafHostEditReq.LogOnlyMode,
		"TransportJSON":        wafHostEditReq.TransportJSON,
		"CustomHeadersJSON":    wafHostEditReq.CustomHeadersJSON,
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", wafHostEditReq.CODE).Updates(hostMap).Error

	return err
}
func (receiver *WafHostService) GetDetailApi(req request.WafHostDetailReq) model.Hosts {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("CODE=?", req.CODE).Find(&webHost)
	return webHost
}
func (receiver *WafHostService) GetDetailByCodeApi(code string) model.Hosts {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("CODE=?", code).Find(&webHost)
	return webHost
}
func (receiver *WafHostService) GetListApi(req request.WafHostSearchReq) ([]model.Hosts, int64, error) {
	var list []model.Hosts
	var total int64 = 0

	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	if len(req.Code) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " code=? "
	}
	for _, by := range splitFilterBys {

		if len(by) > 0 {
			if !validfield.IsValidHostFilterField(by) {
				return nil, 0, errors.New("输入过滤字段不合法")
			}
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " " + by + " like ? "
		}
	}
	//where字段赋值
	if len(req.Code) > 0 {
		whereValues = append(whereValues, req.Code)
	}
	for _, val := range splitFilterValues {
		if len(val) > 0 {
			whereValues = append(whereValues, "%"+val+"%")
		}
	}

	orderInfo := ""

	/**
	排序
	*/
	if req.SortBy != "" {
		if receiver.isValidSortField(req.SortBy) {
			if req.SortDescending == "desc" {
				orderInfo = req.SortBy + " desc"
			} else {
				orderInfo = req.SortBy + " asc"
			}
		} else {
			return nil, 0, errors.New("输入排序字段不合法")
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafHostService) DelHostApi(req request.WafHostDelReq) (model.Hosts, error) {
	var webhost model.Hosts
	err := global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).First(&webhost).Error
	if webhost.GLOBAL_HOST == 1 {
		return model.Hosts{}, errors.New("全局网站不允许单独删除")
	}
	if err != nil {
		return model.Hosts{}, err
	}
	err = global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).Delete(model.Hosts{}).Error
	//删除规则
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.Rules{}).Error
	//删除Anticc
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.AntiCC{}).Error
	//删除禁用ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPBlockList{}).Error
	//删除禁用url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLBlockList{}).Error
	//删除隐私保护url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.LDPUrl{}).Error
	//删除白名单ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPAllowList{}).Error
	//删除白名单URL
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLAllowList{}).Error
	//删除用户名和密码访问
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.HttpAuthBase{}).Error
	return webhost, err
}
func (receiver *WafHostService) ModifyGuardStatusApi(req request.WafHostGuardStatusReq) error {
	hostMap := map[string]interface{}{
		"GUARD_STATUS": req.GUARD_STATUS,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("CODE=?", req.CODE).Updates(hostMap).Error
	return err
}
func (receiver *WafHostService) ModifyStartStatusApi(req request.WafHostStartStatusReq) error {
	hostMap := map[string]interface{}{
		"START_STATUS": req.START_STATUS,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("CODE=?", req.CODE).Updates(hostMap).Error
	return err
}
func (receiver *WafHostService) GetAllHostApi() []model.Hosts {
	var webHosts []model.Hosts
	global.GWAF_LOCAL_DB.Order("global_host desc").Find(&webHosts)
	return webHosts
}

// GetAllRunningHostApi 获取所有正在启动的主机
func (receiver *WafHostService) GetAllRunningHostApi() []model.Hosts {
	var webHosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("global_host <>?", 1).Where("start_status = ?", 0).Find(&webHosts)
	return webHosts
}

func (receiver *WafHostService) CheckPortExistApi(port int) int64 {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("port=?", port).Count(&total)
	return total
}

func (receiver *WafHostService) CheckAvailablePortExistApi(port int) int64 {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(" start_status = 0 and port=?", port).Count(&total)
	return total
}

func (receiver *WafHostService) IsEmptyHost() bool {
	var total int64 = 0
	err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("global_host=?", 0).Count(&total).Error
	if err == nil {
		if total == 0 {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

// GetHostBySSLConfigId 通过SSL绑定ID获取主机信息
func (receiver *WafHostService) GetHostBySSLConfigId(sslId string) []model.Hosts {
	var webHosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("bind_ssl_id=?", sslId).Find(&webHosts)
	return webHosts
}

// UpdateSSLInfo 更新ssl证书信息
func (receiver *WafHostService) UpdateSSLInfo(certContent string, keyContent string, hostCode string) error {
	hostMap := map[string]interface{}{
		"Certfile":    certContent,
		"Keyfile":     keyContent,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", hostCode).Updates(hostMap).Error
	return err
}

// UpdateSSLInfoAndBindId 更新ssl证书信息 有绑定ID 说明是新来的
func (receiver *WafHostService) UpdateSSLInfoAndBindId(certContent string, keyContent string, hostCode string, bindId string) error {
	hostMap := map[string]interface{}{
		"BindSslId":   bindId,
		"Certfile":    certContent,
		"Keyfile":     keyContent,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", hostCode).Updates(hostMap).Error
	return err
}

/*
*
判断是否合法
*/
func (receiver *WafHostService) isValidSortField(field string) bool {
	var allowedSortFields = []string{"create_time"}

	for _, allowedField := range allowedSortFields {
		if field == allowedField {
			return true
		}
	}
	return false
}

// 查询所有SSL证书的
func (receiver *WafHostService) GetAllSSLHost() ([]model.Hosts, int64, error) {
	var list []model.Hosts
	var total int64 = 0

	/**排序*/
	orderInfo := "create_time desc"

	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("ssl =? ", 1).Order(orderInfo).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("ssl =? ", 1).Count(&total)

	return list, total, nil
}

// 查询所有SSL证书的(只看绑定过的主机信息)
func (receiver *WafHostService) GetAllSSLBindHost() ([]model.Hosts, int64, error) {
	var list []model.Hosts
	var total int64 = 0

	/**排序*/
	orderInfo := "create_time desc"

	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("ssl =? and bind_ssl_id <> ?", 1, "").Order(orderInfo).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("ssl =? and bind_ssl_id <> ?", 1, "").Count(&total)

	return list, total, nil
}

// ModifyAllGuardStatusApi 新增批量修改防御状态的方法
func (receiver *WafHostService) ModifyAllGuardStatusApi(req request.WafHostBatchGuardStatusReq) error {
	hostMap := map[string]interface{}{
		"GUARD_STATUS": req.GUARD_STATUS,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}

	// 更新所有非全局主机的防御状态，且只更新与目标状态不同的主机
	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("GLOBAL_HOST <> ? AND GUARD_STATUS <> ?", 1, req.GUARD_STATUS).Updates(hostMap).Error
	return err
}

// CopyConfigApi 复制配置
func (receiver *WafHostService) CopyConfigApi(req request.WafHostBatchCopyConfigReq) error {
	// 获取源主机信息
	sourceHost := receiver.GetDetailByCodeApi(req.SourceHostCode)
	if sourceHost.Code == "" {
		return errors.New("源主机不存在")
	}

	// 获取目标主机信息
	targetHost := receiver.GetDetailByCodeApi(req.TargetHostCode)
	if targetHost.Code == "" {
		return errors.New("目标主机不存在")
	}

	// 开始事务
	tx := global.GWAF_LOCAL_DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 遍历要复制的模块
	for _, module := range req.Modules {
		switch module {
		case "cache":
			// 复制缓存配置
			err := receiver.copyCacheConfig(tx, sourceHost, targetHost)
			if err != nil {
				tx.Rollback()
				return errors.New("复制缓存配置失败: " + err.Error())
			}
		// 可以在这里添加其他模块的复制逻辑
		// case "defense":
		//     err := receiver.copyDefenseConfig(tx, sourceHost, targetHost)
		// case "ssl":
		//     err := receiver.copySSLConfig(tx, sourceHost, targetHost)
		default:
			tx.Rollback()
			return errors.New("不支持的模块: " + module)
		}
	}

	// 提交事务
	return tx.Commit().Error
}

// copyCacheConfig 复制缓存配置
func (receiver *WafHostService) copyCacheConfig(tx *gorm.DB, sourceHost, targetHost model.Hosts) error {
	// 解析源主机的缓存配置
	var sourceCacheConfig model.CacheConfig
	if sourceHost.CacheJSON != "" {
		err := json.Unmarshal([]byte(sourceHost.CacheJSON), &sourceCacheConfig)
		if err != nil {
			return errors.New("解析源主机缓存配置失败: " + err.Error())
		}
	}

	// 将缓存配置应用到目标主机
	cacheJSON, err := json.Marshal(sourceCacheConfig)
	if err != nil {
		return errors.New("序列化缓存配置失败: " + err.Error())
	}

	// 更新目标主机的缓存配置和开启状态
	updateMap := map[string]interface{}{
		"CacheJSON":   string(cacheJSON),
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err = tx.Model(&model.Hosts{}).Where("CODE = ?", targetHost.Code).Updates(updateMap).Error
	if err != nil {
		return errors.New("更新目标主机缓存配置失败: " + err.Error())
	}

	// 复制缓存规则
	err = receiver.copyCacheRules(tx, sourceHost.Code, targetHost.Code)
	if err != nil {
		return errors.New("复制缓存规则失败: " + err.Error())
	}

	return nil
}

// copyCacheRules 复制缓存规则
func (receiver *WafHostService) copyCacheRules(tx *gorm.DB, sourceHostCode, targetHostCode string) error {
	// 查询源主机的所有缓存规则
	var sourceCacheRules []model.CacheRule
	err := tx.Where("host_code = ?", sourceHostCode).Find(&sourceCacheRules).Error
	if err != nil {
		return errors.New("查询源主机缓存规则失败: " + err.Error())
	}

	// 如果源主机没有缓存规则，直接返回
	if len(sourceCacheRules) == 0 {
		return nil
	}

	// 先删除目标主机的现有缓存规则
	err = tx.Where("host_code = ?", targetHostCode).Delete(&model.CacheRule{}).Error
	if err != nil {
		return errors.New("删除目标主机现有缓存规则失败: " + err.Error())
	}

	// 复制缓存规则到目标主机
	for _, rule := range sourceCacheRules {
		newRule := model.CacheRule{
			BaseOrm:       rule.BaseOrm,
			HostCode:      targetHostCode, // 更改为目标主机代码
			RuleName:      rule.RuleName,
			RuleType:      rule.RuleType,
			RuleContent:   rule.RuleContent,
			ParamType:     rule.ParamType,
			CacheTime:     rule.CacheTime,
			Priority:      rule.Priority,
			RequestMethod: rule.RequestMethod,
			Remarks:       rule.Remarks,
		}
		// 生成新的ID和时间戳
		newRule.Id = uuid.GenUUID()
		newRule.USER_CODE = global.GWAF_USER_CODE
		newRule.CREATE_TIME = customtype.JsonTime(time.Now())
		newRule.UPDATE_TIME = customtype.JsonTime(time.Now())

		err = tx.Create(&newRule).Error
		if err != nil {
			return errors.New("创建缓存规则失败: " + err.Error())
		}
	}

	return nil
}

// GetHostsByGuardStatus 获取指定防御状态的主机
func (receiver *WafHostService) GetHostsByGuardStatus(guardStatus int) []model.Hosts {
	var webHosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("global_host <> ? AND guard_status = ? ", 1, guardStatus).Find(&webHosts)
	return webHosts
}
