package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"encoding/json"
	"github.com/edwingeng/deque"
	uuid "github.com/satori/go.uuid"
	"sync/atomic"
	"time"
)

/*
*
初始化队列
*/
func InitDequeEngine() {
	global.GQEQUE_DB = deque.NewDeque()
	global.GQEQUE_LOG_DB = deque.NewDeque()
	global.GQEQUE_STATS_DB = deque.NewDeque()
	global.GQEQUE_STATS_UPDATE_DB = deque.NewDeque()
	global.GQEQUE_MESSAGE_DB = deque.NewDeque()
}

/*
*
处理队列信息
*/
func ProcessDequeEngine() {
	zlog.Info("ProcessDequeEngine start")
	for {
		global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
		for !global.GQEQUE_DB.Empty() {
			weblogbean := global.GQEQUE_DB.PopFront()
			if weblogbean != nil {
				global.GWAF_LOCAL_DB.Create(weblogbean)
			}
		}
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			zlog.Debug("正在切换数据库等待中队列")

		} else {
			var webLogArray []innerbean.WebLog
			for !global.GQEQUE_LOG_DB.Empty() {
				atomic.AddUint64(&global.GWAF_RUNTIME_LOG_PROCESS, 1) // 原子增加计数器
				weblogbean := global.GQEQUE_LOG_DB.PopFront()
				if weblogbean != nil {
					// 进行类型断言将其转为具体的结构
					if logValue, ok := weblogbean.(innerbean.WebLog); ok {
						webLogArray = append(webLogArray, logValue)
					} else {
						//插入其他类型内容
						global.GWAF_LOCAL_LOG_DB.Create(weblogbean)
					}
				}
			}
			if len(webLogArray) > 0 {
				global.GWAF_LOCAL_LOG_DB.CreateInBatches(webLogArray, global.GDATA_BATCH_INSERT)
			}
		}

		for !global.GQEQUE_STATS_DB.Empty() {
			bean := global.GQEQUE_STATS_DB.PopFront()
			global.GWAF_LOCAL_STATS_DB.Create(bean)
		}
		for !global.GQEQUE_STATS_UPDATE_DB.Empty() {
			bean := global.GQEQUE_STATS_UPDATE_DB.PopFront()
			// 进行类型断言将其转为具体的结构
			if UpdateValue, ok := bean.(innerbean.UpdateModel); ok {
				global.GWAF_LOCAL_STATS_DB.Model(UpdateValue.Model).Where(UpdateValue.Query,
					UpdateValue.Args...).Updates(UpdateValue.Update)
			}
		}
		for !global.GQEQUE_MESSAGE_DB.Empty() {
			messageinfo := global.GQEQUE_MESSAGE_DB.PopFront().(interface{})
			isCanSend := false
			switch messageinfo.(type) {
			case innerbean.RuleMessageInfo:
				rulemessage := messageinfo.(innerbean.RuleMessageInfo)
				couter := 1
				if global.GCACHE_WAFCACHE.IsKeyExist(rulemessage.RuleInfo) {
					hitCounter, isok := global.GCACHE_WAFCACHE.GetInt(rulemessage.RuleInfo)
					if isok == nil {
						if hitCounter == 3 || hitCounter == 30 {
							isCanSend = true
						}
						couter = couter + 1
					}
				} else {
					isCanSend = true
				}
				global.GCACHE_WAFCACHE.SetWithTTl(rulemessage.RuleInfo, 1, 30*time.Minute)
				if isCanSend {
					if global.GWAF_NOTICE_ENABLE == false {
						zlog.Info("通知关闭状态")
					} else {
						utils.NotifyHelperApp.SendRuleInfo(rulemessage)
					}

				}
				if rulemessage.BaseMessageInfo.OperaType == "命中保护规则" {
					//发送websocket
					for _, ws := range global.GWebSocket.SocketMap {

						if ws != nil {
							//写入ws数据
							msgBytes, err := json.Marshal(model.MsgPacket{
								MsgCode: "200",
								MsgDataPacket: model.MsgDataPacket{
									MessageId:           uuid.NewV4().String(),
									MessageType:         "命中保护规则",
									MessageData:         rulemessage.RuleInfo + rulemessage.Ip,
									MessageAttach:       nil,
									MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
									MessageUnReadStatus: true,
								},
								MsgCmdType: "Info",
							})
							err = ws.WriteMessage(1, msgBytes)
							if err != nil {
								continue
							}
						}
					}
				}
				break
			case innerbean.OperatorMessageInfo:
				operatorMessage := messageinfo.(innerbean.OperatorMessageInfo)
				utils.NotifyHelperApp.SendNoticeInfo(operatorMessage)
				break
			case innerbean.UpdateResultMessageInfo:
				//升级结果
				updatemessage := messageinfo.(innerbean.UpdateResultMessageInfo)
				//发送websocket
				for _, ws := range global.GWebSocket.SocketMap {
					if ws != nil {
						//写入ws数据
						msgBytes, err := json.Marshal(model.MsgPacket{
							MsgCode: "200",
							MsgDataPacket: model.MsgDataPacket{
								MessageId:           uuid.NewV4().String(),
								MessageType:         "升级结果",
								MessageData:         updatemessage.Msg,
								MessageAttach:       nil,
								MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
								MessageUnReadStatus: true,
							},
							MsgCmdType: "Info",
						})
						err = ws.WriteMessage(1, msgBytes)
						if err != nil {
							zlog.Info("发送websocket错误", err)
							continue
						}
					}
				}
				break
			}

			//zlog.Info("MESSAGE", messageinfo)
		}
		time.Sleep((100 * time.Millisecond))
		global.GWAF_MEASURE_PROCESS_DEQUEENGINE.WriteData(time.Now().UnixNano() / 1e6)
	}
}
