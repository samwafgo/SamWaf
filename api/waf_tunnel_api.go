package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/model/waftunnelmodel"
	"SamWaf/utils"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strconv"
	"strings"
)

type WafTunnelApi struct {
}

func (w *WafTunnelApi) AddApi(c *gin.Context) {
	var req request.WafTunnelAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		portStrArray := strings.Split(req.Port, ",")
		protocol := strings.ToLower(req.Protocol)

		for _, portItem := range portStrArray {
			portItem = strings.TrimSpace(portItem)
			if portItem == "" {
				continue
			}

			port, err := strconv.Atoi(portItem)
			if err != nil {
				continue
			}

			// 根据协议类型检测端口
			var isUsed bool
			switch protocol {
			case "tcp":
				isUsed = utils.TCPPortCheck(port) // TCP端口检测
			case "udp":
				isUsed = utils.UDPPortCheck(port) // UDP端口检测
			default:
				response.FailWithMessage("协议不支持", c)
				return
			}

			if isUsed {
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OpResultMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "端口告警", Server: global.GWAF_CUSTOM_SERVER_NAME},
					Msg:             fmt.Sprintf("%s端口 %d 已被占用", strings.ToUpper(protocol), port),
					Success:         "true",
				})
				response.FailWithMessage(fmt.Sprintf("%s端口 %d 已被占用", strings.ToUpper(protocol), port), c)
				return
			}
		}
		cnt := wafTunnelService.CheckIsExistApi(req)
		if cnt == 0 {
			tunnel, err := wafTunnelService.AddApi(req)

			if err == nil {
				//发送新增通知信息
				var chanInfo = spec.ChanCommon{
					Type:    enums.ChanComTypeTunnel,
					OpType:  enums.OP_TYPE_NEW,
					Content: wafTunnelService.GetDetailByIdApi(tunnel.Id),
				}
				global.GWAF_CHAN_COMMON_MSG <- chanInfo
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前记录已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTunnelApi) GetDetailApi(c *gin.Context) {
	var req request.WafTunnelDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTunnelService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTunnelApi) GetListApi(c *gin.Context) {
	var req request.WafTunnelSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		Tunnel, total, _ := wafTunnelService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      Tunnel,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTunnelApi) DelApi(c *gin.Context) {
	var req request.WafTunnelDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		tunnel := wafTunnelService.GetDetailByIdApi(req.Id)
		err = wafTunnelService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			//发送删除通知信息
			var chanInfo = spec.ChanCommon{
				Type:       enums.ChanComTypeTunnel,
				OpType:     enums.OP_TYPE_DELETE,
				OldContent: tunnel,
			}
			global.GWAF_CHAN_COMMON_MSG <- chanInfo
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTunnelApi) ModifyApi(c *gin.Context) {
	var req request.WafTunnelEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		oldTunnel := wafTunnelService.GetDetailByIdApi(req.Id)
		err = wafTunnelService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			newTunnel := wafTunnelService.GetDetailByIdApi(req.Id)

			//发送修改通知信息
			var chanInfo = spec.ChanCommon{
				Type:       enums.ChanComTypeTunnel,
				OpType:     enums.OP_TYPE_UPDATE,
				Content:    newTunnel,
				OldContent: oldTunnel,
			}
			global.GWAF_CHAN_COMMON_MSG <- chanInfo
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetTunnelConnectionsApi 获取隧道连接信息API
func (w *WafTunnelApi) GetTunnelConnectionsApi(c *gin.Context) {
	var req request.WafTunnelConnReq
	err := c.ShouldBind(&req)
	if err == nil {
		tunnel, err := wafTunnelService.GetTunnelConnections(req.ID)
		if err != nil {
			response.FailWithMessage("获取隧道连接信息失败: "+err.Error(), c)
			return
		}
		// 获取端口列表
		portStrArray := strings.Split(tunnel.Port, ",")
		portInfoList := make([]map[string]interface{}, 0)

		for _, portStr := range portStrArray {
			portStr = strings.TrimSpace(portStr)
			if portStr == "" {
				continue
			}

			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			// 从全局变量中获取连接信息
			tcpSourceCount := 0
			tcpTargetCount := 0
			udpSourceCount := 0
			udpTargetCount := 0

			// TCP来源连接IP列表
			tcpSourceIPs := []map[string]string{}
			// UDP来源连接IP列表
			udpSourceIPs := []map[string]string{}

			// 获取TCP连接数和IP列表
			if globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE != nil {
				tcpSourceCount = globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.TCPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeSource)
				tcpTargetCount = globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.TCPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeTarget)
				udpSourceCount = globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.UDPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeSource)
				udpTargetCount = globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.UDPConnections.GetPortConnsCountByType(port, waftunnelmodel.ConnTypeTarget)

				// 获取TCP来源连接IP列表
				tcpSourceIPList := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.TCPConnections.GetPortConnsInfo(port, waftunnelmodel.ConnTypeSource)
				for _, ip := range tcpSourceIPList {
					// 获取IP归属地区
					region := utils.GetCountry(ip)
					tcpSourceIPs = append(tcpSourceIPs, map[string]string{
						"ip":     ip,
						"region": fmt.Sprintf("%v", region),
					})
				}

				// 获取UDP来源连接IP列表
				udpSourceIPList := globalobj.GWAF_RUNTIME_OBJ_TUNNEL_ENGINE.UDPConnections.GetPortConnsInfo(port, waftunnelmodel.ConnTypeSource)
				for _, ip := range udpSourceIPList {
					// 获取IP归属地区
					region := utils.GetCountry(ip)
					udpSourceIPs = append(udpSourceIPs, map[string]string{
						"ip":     ip,
						"region": fmt.Sprintf("%v", region),
					})
				}
			}

			portInfo := map[string]interface{}{
				"port":             port,
				"tcp_source_count": tcpSourceCount,
				"tcp_target_count": tcpTargetCount,
				"udp_source_count": udpSourceCount,
				"udp_target_count": udpTargetCount,
				"tcp_source_ips":   tcpSourceIPs,
				"udp_source_ips":   udpSourceIPs,
			}

			portInfoList = append(portInfoList, portInfo)
		}

		// 获取连接的IP列表
		connInfo := map[string]interface{}{
			"tunnel_info": tunnel,
			"port_info":   portInfoList,
			"protocol":    tunnel.Protocol,
		}

		response.OkWithDetailed(connInfo, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
