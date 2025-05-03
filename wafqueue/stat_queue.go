package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"time"
)

/*
*
处理Stat队列信息
*/
func ProcessStatDequeEngine() {
	for {
		select {
		case <-global.GWAF_QUEUE_SHUTDOWN_SIGNAL:
			zlog.Info("统计队列处理协程收到关闭信号，正在退出...")
			return
		default:
			for !global.GQEQUE_STATS_DB.Empty() {
				dequeue, ok := global.GQEQUE_STATS_DB.Dequeue()
				if ok {
					global.GWAF_LOCAL_STATS_DB.Create(dequeue)
				}
			}
			for !global.GQEQUE_STATS_UPDATE_DB.Empty() {
				bean, ok := global.GQEQUE_STATS_UPDATE_DB.Dequeue()
				if ok {
					// 进行类型断言将其转为具体的结构
					if UpdateValue, ok := bean.(innerbean.UpdateModel); ok {
						global.GWAF_LOCAL_STATS_DB.Model(UpdateValue.Model).Where(UpdateValue.Query,
							UpdateValue.Args...).Updates(UpdateValue.Update)
					}
				}

			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
