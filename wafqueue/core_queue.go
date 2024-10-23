package wafqueue

import (
	"SamWaf/global"
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
					global.GWAF_LOCAL_DB.Create(bean)
				}
			}

		}
		time.Sleep(100 * time.Millisecond)
	}
}
