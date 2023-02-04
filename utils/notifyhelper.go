package utils

import (
	"SamWaf/global"
	"SamWaf/utils/zlog"
	"SamWaf/wechat"
	"fmt"
)

type NotifyHelper struct {
}

var NotifyHelperApp = new(NotifyHelper)

func (receiver *NotifyHelper) SendInfo(title string, content string, remarks string) {
	if global.GCACHE_WECHAT_ACCESS == "" {
		zlog.Error("未初始化wechat")
		return
	}
	content = fmt.Sprintf("服务器：%s ", global.GWAF_CUSTOM_SERVER_NAME) + content
	tm, err := wechat.BuildTemplateMessage("oUBYM65NIBB2_QhApG7DgOl6A0FU",
		"E0nquOCrrTcMQr6BsyhBraEq6-KukkjD5ZblpPbCcsg", title, content, remarks)
	if err != nil {
		zlog.Error("构造失败", err)
	} else {
		ptm, ptmerr := wechat.PushTemplateMessage(global.GCACHE_WECHAT_ACCESS, tm)
		if ptmerr != nil {
			zlog.Error("推送失败", ptmerr)
		} else if ptm.ErrCode != 0 {
			// 微信服务器返回错误
			zlog.Info("Error occurred when pushing message: " + ptm.ErrMsg)
		} else {
			zlog.Info("推送成功")
		}
	}

}
