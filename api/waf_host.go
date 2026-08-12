package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/model/spec"
	"SamWaf/model/wafenginmodel"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafenginecore"
	"SamWaf/wafenginecore/clientip"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafHostAPi struct {
}

// ipSourceConfig 真实客户端IP提取相关配置(api 层校验/规范化的中转结构)
type ipSourceConfig struct {
	Mode         string
	Depth        int
	Header       string
	TrustProxies string
	Provider     string
}

// validIPSourceModes 真实IP来源模式白名单（""=兼容模式，取 X-Forwarded-For 最左）
var validIPSourceModes = map[string]struct{}{
	"": {}, "nic": {}, "header": {}, "xff_depth": {}, "cdn_preset": {},
}

// checkIPSourceConfig 校验并规范化真实客户端IP提取配置。
// 前端传来的值一律不可信：模式/厂商码走白名单；头名只允许 HTTP token 字符并限长(防 CRLF 头注入)；
// 可信网段逐项必须是合法 IP/CIDR。校验通过后就地规范化(去空白、统一分隔符)。
func checkIPSourceConfig(cfg *ipSourceConfig) error {
	cfg.Mode = strings.TrimSpace(cfg.Mode)
	if _, ok := validIPSourceModes[cfg.Mode]; !ok {
		return errors.New("真实IP来源模式不合法")
	}

	cfg.Provider = strings.TrimSpace(cfg.Provider)
	if cfg.Provider != "" {
		if _, ok := clientip.Providers[cfg.Provider]; !ok {
			return errors.New("CDN厂商不合法")
		}
	}

	cfg.Header = strings.TrimSpace(cfg.Header)
	if len(cfg.Header) > 64 {
		return errors.New("真实IP头名长度不能超过64")
	}
	for _, ch := range cfg.Header {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
			return errors.New("真实IP头名只能包含字母、数字、- 和 _")
		}
	}

	if cfg.Depth < 0 || cfg.Depth > 10 {
		return errors.New("可信代理层数需在 1-10 之间")
	}

	// 用户常从 CDN 控制台整段粘贴，逐行/分号/中文逗号都统一成英文逗号
	unified := strings.NewReplacer("\r", ",", "\n", ",", ";", ",", "；", ",", "，", ",").Replace(cfg.TrustProxies)
	var cleaned []string
	for _, item := range strings.Split(unified, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if _, _, err := net.ParseCIDR(item); err != nil {
				return errors.New("可信代理网段不合法: " + item)
			}
		} else if net.ParseIP(item) == nil {
			return errors.New("可信代理网段不合法: " + item)
		}
		cleaned = append(cleaned, item)
	}
	cfg.TrustProxies = strings.Join(cleaned, ",")

	switch cfg.Mode {
	case "header":
		if cfg.Header == "" {
			return errors.New("指定HTTP头模式必须填写真实IP头名")
		}
	case "cdn_preset":
		if cfg.Provider == "" {
			return errors.New("CDN厂商预设模式必须选择CDN厂商")
		}
		return checkCDNPresetTrustSource(cfg)
	}
	return nil
}

// checkCDNPresetTrustSource cdn_preset 模式必须至少有一个可信来源可用(中心库回源段 或 手填可信网段)。
//
// 缺了它保存下去不是"少一层校验"，而是静默降级成更危险的状态：来源判定恒为 false，
// 所有请求都回退成网络层 IP —— 也就是 CDN 回源节点的 IP。于是 CC 防护、IP 黑名单、限速
// 统统作用在回源节点上，一旦触发封禁，封掉的是整个 CDN 节点，表现为全站对所有访客不可用；
// 且日志里记的全是回源 IP，真实攻击者完全看不见。这种"配了等于没配、还更危险"的组合
// 宁可拦在保存这一步，也不能让用户以为已经生效。
func checkCDNPresetTrustSource(cfg *ipSourceConfig) error {
	if strings.TrimSpace(cfg.TrustProxies) != "" {
		return nil // 用户手填了回源段，兜底可用
	}
	if info := waf_service.WafCDNIPServiceApp.GetProviderInfo(cfg.Provider); info != nil && info.Count > 0 {
		return nil // 中心库已拉到该厂商回源段
	}
	name := cfg.Provider
	if p, ok := clientip.Providers[cfg.Provider]; ok {
		name = p.Name
	}
	return errors.New("中心库尚未拉取到 [" + name + "] 的回源段，且未填写可信代理网段：" +
		"这样来源校验会全部失败，WAF 只能取到 CDN 回源节点的IP，一旦触发封禁会误封整个节点导致全站不可访问。" +
		"请到【CDN回源IP】页开启自动拉取或立即拉取一次；若该厂商不开放回源段API(如 EdgeOne/阿里云免费版)，" +
		"请把控制台里的回源IP段填到「可信代理网段」")
}

// AddApi 新增网站防护主机
// @Summary      新增网站防护主机
// @Description  新增一个网站防护主机配置
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostAddReq  true  "主机配置"
// @Success      200   {object}  response.Response{data=string}  "添加成功，返回主机code"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/add [post]
func (w *WafHostAPi) AddApi(c *gin.Context) {
	var req request.WafHostAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		ipCfg := ipSourceConfig{Mode: req.IPSourceMode, Depth: req.IPTrustDepth, Header: req.IPRealHeader,
			TrustProxies: req.IPTrustProxies, Provider: req.CDNProvider}
		if verr := checkIPSourceConfig(&ipCfg); verr != nil {
			response.FailWithMessage(verr.Error(), c)
			return
		}
		req.IPSourceMode, req.IPTrustDepth, req.IPRealHeader = ipCfg.Mode, ipCfg.Depth, ipCfg.Header
		req.IPTrustProxies, req.CDNProvider = ipCfg.TrustProxies, ipCfg.Provider

		//端口从未在本系统加过，检测端口是否被其他应用占用
		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline.Get(req.Port)
		if !svrOk && utils.PortCheck(req.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			//return
			req.START_STATUS = 1 //设置成不能启动
		}
		err = wafHostService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			hostCode, err := wafHostService.AddApi(req)
			if err == nil {
				w.NotifyWaf(hostCode, nil)
				response.OkWithDetailed(hostCode, "添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站和端口已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// BatchCopyConfigApi 批量复制配置API
func (w *WafHostAPi) BatchCopyConfigApi(c *gin.Context) {
	var req request.WafHostBatchCopyConfigReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 验证源主机是否存在
		sourceHost := wafHostService.GetDetailByCodeApi(req.SourceHostCode)
		if sourceHost.Code == "" {
			response.FailWithMessage("源主机不存在", c)
			return
		}

		// 验证目标主机是否存在
		targetHost := wafHostService.GetDetailByCodeApi(req.TargetHostCode)
		if targetHost.Code == "" {
			response.FailWithMessage("目标主机 "+req.TargetHostCode+" 不存在", c)
			return
		}

		// 执行配置复制
		err = wafHostService.CopyConfigApi(req)
		if err != nil {
			response.FailWithMessage("复制配置失败: "+err.Error(), c)
			return
		}

		// 通知WAF引擎更新配置
		global.GWAF_CHAN_HOST <- targetHost

		response.OkWithMessage("复制配置成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取网站防护主机详情
// @Summary      获取网站防护主机详情
// @Description  根据 code 获取单个主机的详细配置
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "主机唯一编码"
// @Success      200   {object}  response.Response{data=model.Hosts}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/detail [get]
func (w *WafHostAPi) GetDetailApi(c *gin.Context) {
	var req request.WafHostDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHost := wafHostService.GetDetailApi(req)
		response.OkWithDetailed(wafHost, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取网站防护主机列表
// @Summary      获取网站防护主机列表
// @Description  分页查询网站防护主机列表
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/list [post]
func (w *WafHostAPi) GetListApi(c *gin.Context) {
	var req request.WafHostSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafHosts, total, _ := wafHostService.GetListApi(req)
		hostCodes := make([]string, 0, len(wafHosts))
		for _, srcHost := range wafHosts {
			if srcHost.Code != "" {
				hostCodes = append(hostCodes, srcHost.Code)
			}
		}
		todayStatsMap := waf_service.WafStatServiceApp.GetTodaySiteStatsByHostCodes(hostCodes)
		// 初始化返回结果列表
		var repList []response2.HostRep
		for _, srcHost := range wafHosts {
			var healthy []wafenginmodel.HostHealthy
			if srcHost.IsEnableLoadBalance == 0 {
				backendHealthy := wafenginecore.GetBackendHealthy(srcHost.Code, "single")
				if backendHealthy != nil {
					healthy = append(healthy, *backendHealthy)
				}
			} else {
				//获取负载信息
				loadBalances := waf_service.WafLoadBalanceServiceApp.GetListByHostCodeApi(srcHost.Code)
				// 检查每个后端服务器
				for i, _ := range loadBalances {
					backendHealthy := wafenginecore.GetBackendHealthy(srcHost.Code, strconv.Itoa(i))
					if backendHealthy != nil {
						healthy = append(healthy, *backendHealthy)
					}
				}
			}
			rep := response2.HostRep{
				Hosts:              srcHost,
				RealTimeConnectCnt: wafenginecore.GetActiveConnectCnt(srcHost.Code),
				RealTimeQps:        wafenginecore.GetQPS(srcHost.Code),
				TodayPvCount:       todayStatsMap[srcHost.Code].TodayPvCount,
				TodayUvCount:       todayStatsMap[srcHost.Code].TodayUvCount,
				TodayAttackCount:   todayStatsMap[srcHost.Code].TodayAttackCount,
				TodayTrafficIn:     todayStatsMap[srcHost.Code].TodayTrafficIn,
				TodayTrafficOut:    todayStatsMap[srcHost.Code].TodayTrafficOut,
				HealthyStatus:      healthy,
			}
			repList = append(repList, rep)
		}
		response.OkWithDetailed(response.PageResult{
			List:      repList,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafHostAPi) GetAllListApi(c *gin.Context) {
	wafHosts := wafHostService.GetAllHostApi()
	allHostRep := make([]response2.AllHostRep, len(wafHosts)) // 创建数组
	for i, _ := range wafHosts {
		var hostDisplay string
		var preHost string = fmt.Sprintf("%s:%d", wafHosts[i].Host, wafHosts[i].Port)

		// 构建括号内的内容
		var bracketContent []string

		// 如果有昵称，优先显示昵称
		if wafHosts[i].Nickname != "" {
			bracketContent = append(bracketContent, wafHosts[i].Nickname)
		}

		// 如果是SSL，添加SSL标识
		if wafHosts[i].Ssl == 1 {
			bracketContent = append(bracketContent, "SSL")
		}

		// 如果有备注，添加备注
		if wafHosts[i].REMARKS != "" {
			bracketContent = append(bracketContent, wafHosts[i].REMARKS)
		}

		// 构建最终的Host显示字符串
		if len(bracketContent) > 0 {
			hostDisplay = fmt.Sprintf("%s:%d(%s)", wafHosts[i].Host, wafHosts[i].Port, strings.Join(bracketContent, ","))
		} else {
			hostDisplay = fmt.Sprintf("%s:%d", wafHosts[i].Host, wafHosts[i].Port)
		}

		allHostRep[i] = response2.AllHostRep{
			Host:     hostDisplay,
			Code:     wafHosts[i].Code,
			PreHost:  preHost,
			Nickname: wafHosts[i].Nickname,
		}
	}
	response.OkWithDetailed(allHostRep, "获取成功", c)
}

// GetDomainsByHostCodeApi 通过主机code获取所有关联的域名信息
func (w *WafHostAPi) GetDomainsByHostCodeApi(c *gin.Context) {
	var req request.WafHostAllDomainsReq
	err := c.ShouldBind(&req)
	if err == nil {
		if req.CODE == "" {
			response.FailWithMessage("请传入正确的主机信息", c)
			return
		}
		wafHostBean := wafHostService.GetDetailByCodeApi(req.CODE)
		if wafHostBean.Code == "" {
			response.FailWithMessage("未找到该主机信息", c)
			return
		}
		allHostRep := make([]response2.AllDomainRep, 0) // 创建数组

		allHostRep = append(allHostRep, response2.AllDomainRep{
			Host: fmt.Sprintf("%s", wafHostBean.Host),
			Code: req.CODE,
		})
		//如果存在一个主机绑定了多个域名的情况
		if wafHostBean.BindMoreHost != "" {
			lines := strings.Split(wafHostBean.BindMoreHost, "\n")
			for _, line := range lines {
				allHostRep = append(allHostRep, response2.AllDomainRep{
					Host: fmt.Sprintf("%s", line),
					Code: req.CODE,
				})
			}
		}
		response.OkWithDetailed(allHostRep, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}

}

// DelHostApi 删除网站防护主机
// @Summary      删除网站防护主机
// @Description  根据 code 删除网站防护主机配置
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "主机唯一编码"
// @Success      200   {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/del [get]
func (w *WafHostAPi) DelHostApi(c *gin.Context) {
	var req request.WafHostDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		host, err := wafHostService.DelHostApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyDelWaf(host)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyHostApi 编辑网站防护主机
// @Summary      编辑网站防护主机
// @Description  修改网站防护主机配置信息
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostEditReq  true  "主机配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/edit [post]
func (w *WafHostAPi) ModifyHostApi(c *gin.Context) {
	var req request.WafHostEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		ipCfg := ipSourceConfig{Mode: req.IPSourceMode, Depth: req.IPTrustDepth, Header: req.IPRealHeader,
			TrustProxies: req.IPTrustProxies, Provider: req.CDNProvider}
		if verr := checkIPSourceConfig(&ipCfg); verr != nil {
			response.FailWithMessage(verr.Error(), c)
			return
		}
		req.IPSourceMode, req.IPTrustDepth, req.IPRealHeader = ipCfg.Mode, ipCfg.Depth, ipCfg.Header
		req.IPTrustProxies, req.CDNProvider = ipCfg.TrustProxies, ipCfg.Provider

		wafHostOld := wafHostService.GetDetailByCodeApi(req.CODE)
		//端口从未在本系统加过，检测端口是否被其他应用占用

		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline.Get(req.Port)
		if !svrOk && utils.PortCheck(req.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			req.START_STATUS = 1 //设置成不能启动
		}
		err = wafHostService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(req.CODE, wafHostOld)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyGuardStatusApi 修改主机防御状态
// @Summary      修改主机防御状态
// @Description  开启或关闭指定主机的WAF防御
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardStatusReq  true  "防御状态参数"
// @Success      200   {object}  response.Response  "状态更新成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/guardstatus [get]
func (w *WafHostAPi) ModifyGuardStatusApi(c *gin.Context) {
	var req request.WafHostGuardStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafHostService.ModifyGuardStatusApi(req)
		if err != nil {
			response.FailWithMessage("更新状态发生错误", c)
		} else {
			wafHost := wafHostService.GetDetailByCodeApi(req.CODE)
			//发送状态改变通知
			global.GWAF_CHAN_HOST <- wafHost
			response.OkWithMessage("状态更新成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// 修改批量修改防御状态的API
func (w *WafHostAPi) ModifyAllGuardStatusApi(c *gin.Context) {
	var req request.WafHostBatchGuardStatusReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 获取需要变更状态的主机（当前状态与目标状态不同的主机）
		hostsToUpdate := wafHostService.GetHostsByGuardStatus(1 - req.GUARD_STATUS)

		if len(hostsToUpdate) == 0 {
			// 如果没有需要更新的主机，直接返回成功
			message := "所有主机已经是"
			if req.GUARD_STATUS == 1 {
				message += "开启防御状态"
			} else {
				message += "关闭防御状态"
			}
			response.FailWithMessage(message, c)
			return
		}

		err = wafHostService.ModifyAllGuardStatusApi(req)
		if err != nil {
			response.FailWithMessage("批量更新防御状态发生错误", c)
			return
		} else {
			// 只通知需要变更状态的主机
			for _, host := range hostsToUpdate {
				// 更新主机的防御状态
				host.GUARD_STATUS = req.GUARD_STATUS
				global.GWAF_CHAN_HOST <- host
			}

			// 根据操作类型返回不同的成功消息
			message := "批量开启防御成功"
			if req.GUARD_STATUS == 0 {
				message = "批量关闭防御成功"
			}

			response.OkWithMessage(message, c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyStartStatusApi 修改主机启动状态
// @Summary      修改主机启动状态
// @Description  启动或停止指定主机的监听服务
// @Tags         网站防护-主机管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostStartStatusReq  true  "启动状态参数"
// @Success      200   {object}  response.Response  "状态更新成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/host/startstatus [get]
func (w *WafHostAPi) ModifyStartStatusApi(c *gin.Context) {
	var req request.WafHostStartStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHostOld := wafHostService.GetDetailByCodeApi(req.CODE)

		_, svrOk := globalobj.GWAF_RUNTIME_OBJ_WAF_ENGINE.ServerOnline.Get(wafHostOld.Port)

		if req.START_STATUS == 0 && !svrOk && utils.PortCheck(wafHostOld.Port) == false {
			//发送websocket 推送消息
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "提示信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
				Msg:             "端口被其他应用占用不能使用,如果使用的宝塔请在Samwaf系统管理-一键修改进行操作",
				Success:         "true",
			})
			response.FailWithMessage("端口被其他应用占用不能开启", c)
			return
		} else {
			err = wafHostService.ModifyStartStatusApi(req)
			if err != nil {
				response.FailWithMessage("更新状态发生错误", c)
			} else {
				//发送状态改变通知
				w.NotifyWaf(req.CODE, wafHostOld)
				response.OkWithMessage("状态更新成功", c)
			}
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafHostAPi) NotifyWaf(hostCode string, oldHostInterface interface{}) {

	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("code = ? ", hostCode).Find(&hosts)
	var chanInfo = spec.ChanCommonHost{
		HostCode:   hostCode,
		Type:       enums.ChanTypeHost,
		Content:    hosts,
		OldContent: oldHostInterface,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

func (w *WafHostAPi) NotifyDelWaf(hosts model.Hosts) {
	//1.如果这个port里面没有了主机 那可以直接停掉服务
	//2.除了第一个情况之外的，把所有他的主机信息和关联信息都干掉

	var chanInfo = spec.ChanCommonHost{
		HostCode: hosts.Code,
		Type:     enums.ChanTypeDelHost,
		Content:  hosts,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
