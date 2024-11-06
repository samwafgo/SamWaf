package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/service/waf_service"
	"fmt"
)

// TaskStatusNotify 汇总通知
func TaskStatusNotify() {
	zlog.Debug("TaskStatusNotify")
	statHomeInfo, err := waf_service.WafStatServiceApp.StatHomeSumDayApi()
	if err == nil {
		noticeStr := fmt.Sprintf("今日访问量：%d 今天恶意访问量:%d 昨日恶意访问量:%d", statHomeInfo.VisitCountOfToday, statHomeInfo.AttackCountOfToday, statHomeInfo.AttackCountOfYesterday)

		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "汇总通知"},
			OperaCnt:        noticeStr,
		})
	} else {
		zlog.Error("TaskStatusNotifyerror", err)
	}

}
