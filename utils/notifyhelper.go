package utils

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/utils/zlog"
	"SamWaf/wechat"
)

type NotifyHelper struct {
}

var NotifyHelperApp = new(NotifyHelper)

func (receiver *NotifyHelper) SendRuleInfo(ruleMessageInfo innerbean.RuleMessageInfo) {
	if global.GCACHE_WECHAT_ACCESS == "" {
		zlog.Error("未初始化wechat")
		return
	}
	ruleMessageInfo.Server = global.GWAF_CUSTOM_SERVER_NAME
	//content = fmt.Sprintf("服务器：%s ", global.GWAF_CUSTOM_SERVER_NAME) + content
	tm, err := wechat.BuildTemplateMessage("oUBYM65NIBB2_QhApG7DgOl6A0FU",
		"RbQR70NpwkVHMLiN_jBr4Swccxu_FuzODuTBNK2DX1w", ruleMessageInfo.ToFormat())
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

func (receiver *NotifyHelper) SendNoticeInfo(operatorMessageInfo innerbean.OperatorMessageInfo) {
	if global.GCACHE_WECHAT_ACCESS == "" {
		zlog.Error("未初始化wechat")
		return
	}
	operatorMessageInfo.Server = global.GWAF_CUSTOM_SERVER_NAME
	//content = fmt.Sprintf("服务器：%s ", global.GWAF_CUSTOM_SERVER_NAME) + content
	tm, err := wechat.BuildTemplateMessage("oUBYM65NIBB2_QhApG7DgOl6A0FU",
		"I4-QACokwNr-v1tM64_E2UwUFtIkSW3v_xa9PocP21I", operatorMessageInfo.ToFormat())
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
