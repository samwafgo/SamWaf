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
	"SamWaf/wafdb/dialect"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

type WafHostService struct{}

var WafHostServiceApp = new(WafHostService)

// normalizeIsEnableResponseBuffering 响应缓冲取值：1开启 0关闭；其它值按开启处理
func normalizeIsEnableResponseBuffering(v int) int {
	if v == 0 {
		return 0
	}
	return 1
}

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
		Code:                      uniCode,
		Host:                      wafHostAddReq.Host,
		Port:                      wafHostAddReq.Port,
		Ssl:                       wafHostAddReq.Ssl,
		GUARD_STATUS:              1,
		REMOTE_SYSTEM:             wafHostAddReq.REMOTE_SYSTEM,
		REMOTE_APP:                wafHostAddReq.REMOTE_APP,
		Remote_host:               wafHostAddReq.Remote_host,
		Remote_port:               wafHostAddReq.Remote_port,
		Remote_ip:                 wafHostAddReq.Remote_ip,
		Certfile:                  wafHostAddReq.Certfile,
		Keyfile:                   wafHostAddReq.Keyfile,
		Nickname:                  wafHostAddReq.Nickname,
		REMARKS:                   wafHostAddReq.REMARKS,
		GLOBAL_HOST:               0,
		DEFENSE_JSON:              wafHostAddReq.DEFENSE_JSON,
		START_STATUS:              wafHostAddReq.START_STATUS,
		EXCLUDE_URL_LOG:           wafHostAddReq.EXCLUDE_URL_LOG,
		IsEnableLoadBalance:       wafHostAddReq.IsEnableLoadBalance,
		LoadBalanceStage:          wafHostAddReq.LoadBalanceStage,
		UnrestrictedPort:          wafHostAddReq.UnrestrictedPort,
		BindSslId:                 wafHostAddReq.BindSslId,
		AutoJumpHTTPS:             wafHostAddReq.AutoJumpHTTPS,
		BindMoreHost:              wafHostAddReq.BindMoreHost,
		IsTransBackDomain:         wafHostAddReq.IsTransBackDomain,
		BindMorePort:              wafHostAddReq.BindMorePort,
		IsEnableHttpAuthBase:      wafHostAddReq.IsEnableHttpAuthBase,
		HttpAuthBaseType:          wafHostAddReq.HttpAuthBaseType,
		HttpAuthPathPrefix:        httpAuthPathPrefix,
		HttpAuthJSON:              wafHostAddReq.HttpAuthJSON,
		ResponseTimeOut:           wafHostAddReq.ResponseTimeOut,
		HealthyJSON:               wafHostAddReq.HealthyJSON,
		InsecureSkipVerify:        wafHostAddReq.InsecureSkipVerify,
		CaptchaJSON:               captchaJSON,
		AntiLeechJSON:             wafHostAddReq.AntiLeechJSON,
		CacheJSON:                 wafHostAddReq.CacheJSON,
		StaticSiteJSON:            wafHostAddReq.StaticSiteJSON,
		DefaultEncoding:           wafHostAddReq.DefaultEncoding,
		LogOnlyMode:               wafHostAddReq.LogOnlyMode,
		TransportJSON:             wafHostAddReq.TransportJSON,
		CustomHeadersJSON:         wafHostAddReq.CustomHeadersJSON,
		CustomResponseHeadersJSON: wafHostAddReq.CustomResponseHeadersJSON,
		ResponseCompressJSON:      wafHostAddReq.ResponseCompressJSON,
		CookieSecurityJSON:        wafHostAddReq.CookieSecurityJSON,
		CsrfJSON:                  wafHostAddReq.CsrfJSON,
		TamperJSON:                wafHostAddReq.TamperJSON,
		UploadSecurityJSON:        wafHostAddReq.UploadSecurityJSON,
		IPMode:                    wafHostAddReq.IPMode,
		DisableHTTP2:              wafHostAddReq.DisableHTTP2,
		IsEnableResponseBuffering: normalizeIsEnableResponseBuffering(wafHostAddReq.IsEnableResponseBuffering),
		AccessJSON:                wafHostAddReq.AccessJSON,
		IPSourceMode:              wafHostAddReq.IPSourceMode,
		IPTrustDepth:              wafHostAddReq.IPTrustDepth,
		IPRealHeader:              wafHostAddReq.IPRealHeader,
		IPTrustProxies:            wafHostAddReq.IPTrustProxies,
		CDNProvider:               wafHostAddReq.CDNProvider,
		GroupCode:                 wafHostAddReq.GroupCode,
		PortListensJSON:           wafHostAddReq.PortListensJSON,
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
	// 改域名同样能把认证中心悬空——效果和删站点一模一样（所有站点失去登录入口），
	// 只是更隐蔽。这里只拦「改之前托管着认证中心、改之后不再托管」这一种情况，
	// 认证中心站点的其它字段（后端地址、证书……）照常可改。
	oldHost := receiver.GetDetailByCodeApi(wafHostEditReq.CODE)
	if used, centerHost := WafAccessConfigServiceApp.IsHostUsedAsCenter(oldHost); used {
		after := model.Hosts{Host: wafHostEditReq.Host, BindMoreHost: wafHostEditReq.BindMoreHost}
		if stillUsed, _ := WafAccessConfigServiceApp.IsHostUsedAsCenter(after); !stillUsed {
			return errors.New("该站点正被统一访问认证用作认证中心（" + centerHost +
				"），改掉域名后所有站点都将失去登录入口。请先到【统一访问认证-认证配置】改用其它域名")
		}
	}
	hostMap := map[string]interface{}{
		"Host": wafHostEditReq.Host,
		"Port": wafHostEditReq.Port,
		"Ssl":  wafHostEditReq.Ssl,
		//"GUARD_STATUS":  0,
		"REMOTE_SYSTEM":             wafHostEditReq.REMOTE_SYSTEM,
		"REMOTE_APP":                wafHostEditReq.REMOTE_APP,
		"Remote_host":               wafHostEditReq.Remote_host,
		"Remote_ip":                 wafHostEditReq.Remote_ip,
		"Remote_port":               wafHostEditReq.Remote_port,
		"Nickname":                  wafHostEditReq.Nickname,
		"REMARKS":                   wafHostEditReq.REMARKS,
		"GLOBAL_HOST":               0,
		"Certfile":                  wafHostEditReq.Certfile,
		"Keyfile":                   wafHostEditReq.Keyfile,
		"UPDATE_TIME":               customtype.JsonTime(time.Now()),
		"DEFENSE_JSON":              wafHostEditReq.DEFENSE_JSON,
		"START_STATUS":              wafHostEditReq.START_STATUS,
		"EXCLUDE_URL_LOG":           wafHostEditReq.EXCLUDE_URL_LOG,
		"IsEnableLoadBalance":       wafHostEditReq.IsEnableLoadBalance,
		"LoadBalanceStage":          wafHostEditReq.LoadBalanceStage,
		"UnrestrictedPort":          wafHostEditReq.UnrestrictedPort,
		"BindSslId":                 wafHostEditReq.BindSslId,
		"AutoJumpHTTPS":             wafHostEditReq.AutoJumpHTTPS,
		"BindMoreHost":              wafHostEditReq.BindMoreHost,
		"IsTransBackDomain":         wafHostEditReq.IsTransBackDomain,
		"BindMorePort":              wafHostEditReq.BindMorePort,
		"IsEnableHttpAuthBase":      wafHostEditReq.IsEnableHttpAuthBase,
		"HttpAuthBaseType":          wafHostEditReq.HttpAuthBaseType,
		"HttpAuthPathPrefix":        wafHostEditReq.HttpAuthPathPrefix,
		"HttpAuthJSON":              wafHostEditReq.HttpAuthJSON,
		"ResponseTimeOut":           wafHostEditReq.ResponseTimeOut,
		"HealthyJSON":               wafHostEditReq.HealthyJSON,
		"InsecureSkipVerify":        wafHostEditReq.InsecureSkipVerify,
		"CaptchaJSON":               wafHostEditReq.CaptchaJSON,
		"AntiLeechJSON":             wafHostEditReq.AntiLeechJSON,
		"CacheJSON":                 wafHostEditReq.CacheJSON,
		"StaticSiteJSON":            wafHostEditReq.StaticSiteJSON,
		"DefaultEncoding":           wafHostEditReq.DefaultEncoding,
		"LogOnlyMode":               wafHostEditReq.LogOnlyMode,
		"TransportJSON":             wafHostEditReq.TransportJSON,
		"CustomHeadersJSON":         wafHostEditReq.CustomHeadersJSON,
		"CustomResponseHeadersJSON": wafHostEditReq.CustomResponseHeadersJSON,
		"ResponseCompressJSON":      wafHostEditReq.ResponseCompressJSON,
		"CookieSecurityJSON":        wafHostEditReq.CookieSecurityJSON,
		"CsrfJSON":                  wafHostEditReq.CsrfJSON,
		"TamperJSON":                wafHostEditReq.TamperJSON,
		"UploadSecurityJSON":        wafHostEditReq.UploadSecurityJSON,
		"IPMode":                    wafHostEditReq.IPMode,
		"DisableHTTP2":              wafHostEditReq.DisableHTTP2,
		"IsEnableResponseBuffering": normalizeIsEnableResponseBuffering(wafHostEditReq.IsEnableResponseBuffering),
		"AccessJSON":                wafHostEditReq.AccessJSON,
		"IPSourceMode":              wafHostEditReq.IPSourceMode,
		"IPTrustDepth":              wafHostEditReq.IPTrustDepth,
		"IPRealHeader":              wafHostEditReq.IPRealHeader,
		"IPTrustProxies":            wafHostEditReq.IPTrustProxies,
		"CDNProvider":               wafHostEditReq.CDNProvider,
		"GroupCode":                 wafHostEditReq.GroupCode,
	}
	// PortListensJSON 指针语义：nil=请求未携带（旧前端/脚本），保持库中原值不写，
	// 防止老客户端把端口监听表抹空导致协议突变；非 nil（含空串）才落库
	if wafHostEditReq.PortListensJSON != nil {
		hostMap["PortListensJSON"] = *wafHostEditReq.PortListensJSON
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", wafHostEditReq.CODE).Updates(hostMap).Error
	if err != nil {
		return err
	}
	// 关掉「网站密码访问」时把在线会话一并作废：留着的话，等哪天再打开开关，
	// 那批旧 Cookie 会直接复活，用户看到的是「刚开的门里已经站着人」。
	if oldHost.IsEnableHttpAuthBase == 1 && wafHostEditReq.IsEnableHttpAuthBase != 1 {
		WafHttpAuthSessionServiceApp.RevokeByHostCode(wafHostEditReq.CODE, model.HttpAuthRevokeByHost)
	}
	return nil
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
	//where字段赋值
	if len(req.Code) > 0 {
		whereValues = append(whereValues, req.Code)
	}
	// 分组筛选：走精确匹配，不并入下面 FilterBy 的 like 通道
	// （短码走 like 会出现 "a" 命中 "abc" 的串组）。
	if len(req.GroupCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		if req.GroupCode == model.HostGroupNone {
			// 存量行落的是 NULL 还是空串取决于数据库，两种都要命中，否则会漏掉一半站点
			whereField = whereField + " (group_code = '' or group_code is null) "
		} else {
			whereField = whereField + " group_code = ? "
			whereValues = append(whereValues, req.GroupCode)
		}
	}
	for i, by := range splitFilterBys {
		if len(by) == 0 {
			continue
		}
		if !validfield.IsValidHostFilterField(by) {
			return nil, 0, errors.New("输入过滤字段不合法")
		}
		val := ""
		if i < len(splitFilterValues) {
			val = splitFilterValues[i]
		}
		if len(val) == 0 {
			continue
		}
		if len(whereField) > 0 {
			whereField += " and "
		}
		if by == "host" {
			whereField += " (host like ? OR nickname like ?) "
			whereValues = append(whereValues, "%"+val+"%", "%"+val+"%")
		} else if by == "port" {
			// 「监听端口」列展示的是这个站的全部监听端口（主端口 + 副端口 + 显式端口表），
			// 只查 port 主端口列会出现"列里明明列着 6800、按 6800 筛却 0 条"。
			// port 是整型列：PostgreSQL 下 `int like '文本'` 直接报错(无隐式转换)，
			// 所以数字走等值、只有文本列走 like，三种数据库通吃。
			if p, convErr := strconv.Atoi(strings.TrimSpace(val)); convErr == nil {
				whereField += " (port = ? or bind_more_port like ? or port_listens_json like ?) "
				whereValues = append(whereValues, p, "%"+val+"%", "%"+val+"%")
			} else {
				whereField += " (bind_more_port like ? or port_listens_json like ?) "
				whereValues = append(whereValues, "%"+val+"%", "%"+val+"%")
			}
		} else if by == "remote_port" {
			// 同上：整型列不能 like，非数字输入直接判定为无结果
			if p, convErr := strconv.Atoi(strings.TrimSpace(val)); convErr == nil {
				whereField += " remote_port = ? "
				whereValues = append(whereValues, p)
			} else {
				whereField += " 1 = 0 "
			}
		} else {
			whereField += " " + by + " like ? "
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

	// 查询错误必须抛出去：吞掉的话前端只会看到"共 0 条数据"，
	// 分不清是"确实没有"还是"这条 SQL 在当前数据库上根本执行不了"
	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Count(&total).Error; err != nil {
		return nil, 0, err
	}

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
	// 认证中心站点删不得。统一访问认证只有「先跳到认证中心登录」这一条路，
	// 中心站点没了就等于所有站点同时失去登录入口 —— 要么全站锁死，要么访问控制静默失效，
	// 两种都不该由一次删站点静悄悄地造成。让用户先去改认证配置，把意图说清楚。
	if used, centerHost := WafAccessConfigServiceApp.IsHostUsedAsCenter(webhost); used {
		return model.Hosts{}, errors.New("该站点正被统一访问认证用作认证中心（" + centerHost +
			"），删除后所有站点都将失去登录入口。请先到【统一访问认证-认证配置】改用其它域名")
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
	//站点没了，它的在线会话也一起作废：站点若被同名重建，旧 Cookie 不该还能用
	WafHttpAuthSessionServiceApp.RevokeByHostCode(req.CODE, model.HttpAuthRevokeByHost)

	// 统一访问认证的残留清理。这三件事必须一起做，否则站点删了配置还在到处生效：
	//   ① 该站点上已签发的子令牌作废（站点若被同名重建，旧 Cookie 不该还能用）
	//   ② 从所有访问账号的授权站点列表里摘掉这个短码（列表空掉的账号会被禁用，
	//      因为"空=全部站点"，直接留空等于把受限账号提权成全站可访问）
	//   ③ 重新发布运行时配置（认证中心站点删不掉，这里只是兜底对齐）
	WafAccessSessionServiceApp.RevokeByHostCode(req.CODE)
	WafAccessAccountServiceApp.RemoveHostCode(req.CODE)
	WafAccessConfigServiceApp.SyncAfterHostChanged()

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
	// 端口引用统一按监听表判定（含显式 port_listens_json、副端口与 AutoJumpHTTPS 隐式 80）：
	// 漏算会导致 RemovePortServer 误关仍在使用的监听
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("start_status = 0 and global_host = 0").Find(&hosts)
	for _, h := range hosts {
		for _, p := range utils.HostListenPorts(h) {
			if p == port {
				return 1
			}
		}
	}
	return 0
}

// ListenConflict 端口协议冲突明细（保存预检与站点列表标记共用）
type ListenConflict struct {
	Port          int    `json:"port"`
	WantProto     string `json:"want_proto"`
	OtherProto    string `json:"other_proto"`
	OtherHost     string `json:"other_host"`
	OtherNickname string `json:"other_nickname"`
	OtherCode     string `json:"other_code"`
}

// CheckPortListensConflict 校验监听表与其它启用站点是否存在「同端口不同协议」冲突。
// excludeCode 排除自身（编辑场景）；对端同样走 ResolveHostListens（含空表派生）。
func (receiver *WafHostService) CheckPortListensConflict(excludeCode string, listens []utils.HostListen) []ListenConflict {
	var conflicts []ListenConflict
	if len(listens) == 0 {
		return conflicts
	}
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("start_status = 0 and global_host = 0 and code != ?", excludeCode).Find(&hosts)
	for _, other := range hosts {
		for _, ol := range utils.ResolveHostListens(other) {
			for _, l := range listens {
				if l.Port == ol.Port && l.Protocol != ol.Protocol {
					conflicts = append(conflicts, ListenConflict{
						Port:          l.Port,
						WantProto:     l.Protocol,
						OtherProto:    ol.Protocol,
						OtherHost:     other.Host,
						OtherNickname: other.Nickname,
						OtherCode:     other.Code,
					})
				}
			}
		}
	}
	return conflicts
}

// FormatListenConflicts 冲突明细转用户可读文案（保存拒绝与预检共用一套话术）
func FormatListenConflicts(conflicts []ListenConflict) string {
	if len(conflicts) == 0 {
		return ""
	}
	var parts []string
	for _, c := range conflicts {
		other := c.OtherHost
		if c.OtherNickname != "" {
			other = other + "（" + c.OtherNickname + "）"
		}
		parts = append(parts, "端口 "+strconv.Itoa(c.Port)+" 已被站点 "+other+" 以 "+strings.ToUpper(c.OtherProto)+
			" 协议监听，本站声明为 "+strings.ToUpper(c.WantProto))
	}
	return strings.Join(parts, "；") + "。同一端口在本机只能是一种协议，请统一协议或更换端口"
}

// ValidatePortListensReq 保存期校验：与引擎运行期的宽容解析不同，用户主动编辑时脏数据一律拒绝。
// 返回按显式表归一后的监听列表（供后续冲突校验复用）。
func (receiver *WafHostService) ValidatePortListensReq(raw string, mainPort int, ssl int, autoJumpHTTPS int) ([]utils.HostListen, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// 列宽 size:2048：MySQL 下超长在严格模式报错含糊、非严格模式截断成坏 JSON 后静默回落派生，必须在保存期拦住
	if len(raw) > 2048 {
		return nil, errors.New("端口监听表过长(超过2048字符)")
	}
	var items []utils.PortListenItem
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return nil, errors.New("端口监听表格式不合法")
	}
	if len(items) == 0 {
		return nil, errors.New("端口监听表不能为空")
	}
	if len(items) > 32 {
		return nil, errors.New("端口监听表最多支持 32 个端口")
	}
	seen := map[int]bool{}
	hasMain := false
	hasHTTPS := false
	for _, it := range items {
		if it.Port < 1 || it.Port > 65535 {
			return nil, errors.New("端口 " + strconv.Itoa(it.Port) + " 超出合法范围(1-65535)")
		}
		proto := strings.ToLower(strings.TrimSpace(it.Proto))
		if proto != utils.ListenProtoHTTP && proto != utils.ListenProtoHTTPS {
			return nil, errors.New("端口 " + strconv.Itoa(it.Port) + " 的协议只能是 http 或 https")
		}
		ipv := strings.ToLower(strings.TrimSpace(it.Ipv))
		if ipv != "" && ipv != utils.ListenIPVBoth && ipv != utils.ListenIPV4 && ipv != utils.ListenIPV6 {
			return nil, errors.New("端口 " + strconv.Itoa(it.Port) + " 的IP版本只能是 both/ipv4/ipv6")
		}
		if strings.TrimSpace(it.Addr) != "" {
			return nil, errors.New("当前版本不支持指定监听地址(addr)")
		}
		if seen[it.Port] {
			return nil, errors.New("端口 " + strconv.Itoa(it.Port) + " 重复")
		}
		seen[it.Port] = true
		if it.Port == mainPort {
			hasMain = true
		}
		if proto == utils.ListenProtoHTTPS {
			hasHTTPS = true
		}
	}
	if !hasMain {
		return nil, errors.New("端口监听表必须包含主端口 " + strconv.Itoa(mainPort))
	}
	if hasHTTPS && ssl != 1 {
		// 只要求开启 SSL，不要求证书文件已就位：自动申请证书流程里证书后到，与老行为持平
		return nil, errors.New("存在 HTTPS 端口时必须启用SSL证书开关")
	}
	return utils.ResolveHostListens(model.Hosts{Port: mainPort, Ssl: ssl, AutoJumpHTTPS: autoJumpHTTPS, PortListensJSON: raw}), nil
}

// PortOverviewSite 端口占用总览里的单个站点引用
type PortOverviewSite struct {
	Code     string `json:"code"`
	Host     string `json:"host"`
	Nickname string `json:"nickname"`
	Proto    string `json:"proto"`
	Ipv      string `json:"ipv"`
	IsMain   bool   `json:"is_main"`
	Implied  bool   `json:"implied"`
}

// PortOverviewRow 端口占用总览行：一个端口在全机的声明汇总
type PortOverviewRow struct {
	Port     int                `json:"port"`
	Proto    string             `json:"proto"` // http / https；冲突时为先声明者协议
	Conflict bool               `json:"conflict"`
	Sites    []PortOverviewSite `json:"sites"`
}

// GetPortOverviewApi 端口占用总览：端口 → 协议 → 占用站点（仅启用的非全局站点），按端口升序
func (receiver *WafHostService) GetPortOverviewApi() []PortOverviewRow {
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("start_status = 0 and global_host = 0").Order("create_time asc").Find(&hosts)
	rowMap := map[int]*PortOverviewRow{}
	var portsOrder []int
	for _, h := range hosts {
		for _, l := range utils.ResolveHostListens(h) {
			row, ok := rowMap[l.Port]
			if !ok {
				row = &PortOverviewRow{Port: l.Port, Proto: l.Protocol}
				rowMap[l.Port] = row
				portsOrder = append(portsOrder, l.Port)
			}
			if row.Proto != l.Protocol {
				row.Conflict = true
			}
			row.Sites = append(row.Sites, PortOverviewSite{
				Code: h.Code, Host: h.Host, Nickname: h.Nickname,
				Proto: l.Protocol, Ipv: l.IPVersion, IsMain: l.IsMain, Implied: l.Implied,
			})
		}
	}
	sort.Ints(portsOrder)
	rows := make([]PortOverviewRow, 0, len(portsOrder))
	for _, p := range portsOrder {
		rows = append(rows, *rowMap[p])
	}
	return rows
}

// HostPortConflictCodes 返回当前处于端口协议冲突中的启用站点 code 集合（列表红标用）
func (receiver *WafHostService) HostPortConflictCodes() map[string]bool {
	res := map[string]bool{}
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("start_status = 0 and global_host = 0").Find(&hosts)
	type occ struct {
		proto string
		codes []string
	}
	portMap := map[int]*occ{}
	for _, h := range hosts {
		for _, l := range utils.ResolveHostListens(h) {
			o, ok := portMap[l.Port]
			if !ok {
				portMap[l.Port] = &occ{proto: l.Protocol, codes: []string{h.Code}}
				continue
			}
			o.codes = append(o.codes, h.Code)
			if o.proto != l.Protocol {
				o.proto = "conflict"
			}
		}
	}
	for _, o := range portMap {
		if o.proto == "conflict" {
			for _, c := range o.codes {
				res[c] = true
			}
		}
	}
	return res
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

	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(dialect.Q("ssl")+" = ? ", 1).Order(orderInfo).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(dialect.Q("ssl")+" = ? ", 1).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	return list, total, nil
}

// 查询所有SSL证书的(只看绑定过的主机信息)
func (receiver *WafHostService) GetAllSSLBindHost() ([]model.Hosts, int64, error) {
	var list []model.Hosts
	var total int64 = 0

	/**排序*/
	orderInfo := "create_time desc"

	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(dialect.Q("ssl")+" = ? and bind_ssl_id <> ?", 1, "").Order(orderInfo).Find(&list).Error; err != nil {
		return nil, 0, err
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(dialect.Q("ssl")+" = ? and bind_ssl_id <> ?", 1, "").Count(&total).Error; err != nil {
		return nil, 0, err
	}

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
		case "response_compress":
			err := receiver.copyResponseCompressConfig(tx, sourceHost, targetHost)
			if err != nil {
				tx.Rollback()
				return errors.New("复制响应压缩配置失败: " + err.Error())
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

// copyResponseCompressConfig 复制响应压缩配置
func (receiver *WafHostService) copyResponseCompressConfig(tx *gorm.DB, sourceHost, targetHost model.Hosts) error {
	var cfg model.ResponseCompressConfig
	if sourceHost.ResponseCompressJSON != "" {
		if err := json.Unmarshal([]byte(sourceHost.ResponseCompressJSON), &cfg); err != nil {
			return errors.New("解析源主机响应压缩配置失败: " + err.Error())
		}
	} else {
		cfg = model.ParseResponseCompressConfig("")
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return errors.New("序列化响应压缩配置失败: " + err.Error())
	}
	updateMap := map[string]interface{}{
		"ResponseCompressJSON": string(out),
		"UPDATE_TIME":          customtype.JsonTime(time.Now()),
	}
	return tx.Model(&model.Hosts{}).Where("CODE = ?", targetHost.Code).Updates(updateMap).Error
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
