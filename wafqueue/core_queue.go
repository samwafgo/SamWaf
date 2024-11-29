package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"time"
)

/*
*
处理核心队列信息
*/
func ProcessCoreDequeEngine() {
	for {
		for !global.GQEQUE_DB.Empty() {
			bean, ok := global.GQEQUE_DB.Dequeue()
			if ok {
				if bean != nil {
					tx := global.GWAF_LOCAL_DB.Create(bean)
					if tx.Error != nil {
						zlog.Error("LocalDBerror", tx.Error.Error())
					}
				}
			}

		}
		for !global.GQEQUE_UPDATE_DB.Empty() {
			bean, ok := global.GQEQUE_UPDATE_DB.Dequeue()
			if ok {
				if bean != nil {
					// 进行类型断言将其转为具体的结构
					if UpdateValue, ok := bean.(innerbean.UpdateModel); ok {
						global.GWAF_LOCAL_DB.Model(UpdateValue.Model).Where(UpdateValue.Query,
							UpdateValue.Args...).Updates(UpdateValue.Update)
					}
				}
			}

		}
		time.Sleep(100 * time.Millisecond)
	}
}
