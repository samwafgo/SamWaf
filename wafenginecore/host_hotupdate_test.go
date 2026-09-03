package wafenginecore

import (
	"testing"

	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// 轻量热更新通道必须把「请求期要读的字段」搬进引擎快照。
//
// 这条用例守的是一个很难查的症状：界面改了、库里存了、接口也读得回来，唯独引擎一直用旧值，
// 重启才生效（因为重启是从库里重新加载的）。紧急模式踩过一次——
// 该通道当时只搬 GUARD_STATUS，开关打开后引擎里的 EmergencyMode 一直是 0。
func TestApplyHostHotUpdate_CarriesRuntimeFields(t *testing.T) {
	h := &wafenginmodel.HostSafe{}
	h.Host.Code = "c1"
	h.Host.GUARD_STATUS = 0
	h.Host.EmergencyMode = 0
	h.Host.EmergencyUntil = 0

	ApplyHostHotUpdate(h, model.Hosts{
		GUARD_STATUS:   1,
		EmergencyMode:  1,
		EmergencyUntil: 1893456000,
	})

	if h.Host.GUARD_STATUS != 1 {
		t.Fatalf("防护开关没有同步进引擎快照")
	}
	if h.Host.EmergencyMode != 1 {
		t.Fatalf("紧急模式开关没有同步进引擎快照——界面会显示已开启，引擎却不生效")
	}
	if h.Host.EmergencyUntil != 1893456000 {
		t.Fatalf("紧急模式到期时间没有同步进引擎快照")
	}
}

// 关闭方向同样要能搬过去：只测开启的话，把赋值写成「只在为 1 时才置位」也能过。
func TestApplyHostHotUpdate_TurnOffAlsoPropagates(t *testing.T) {
	h := &wafenginmodel.HostSafe{}
	h.Host.GUARD_STATUS = 1
	h.Host.EmergencyMode = 1
	h.Host.EmergencyUntil = 1893456000

	ApplyHostHotUpdate(h, model.Hosts{GUARD_STATUS: 0, EmergencyMode: 0, EmergencyUntil: 0})

	if h.Host.GUARD_STATUS != 0 || h.Host.EmergencyMode != 0 || h.Host.EmergencyUntil != 0 {
		t.Fatalf("关闭方向没有同步，引擎会一直停在开启状态: %+v", h.Host)
	}
}

// 不整份替换 HostSafe.Host：该通道有发送方送的是操作前的旧快照，
// 整份覆盖会把刚写进去的配置又抹回去。这条用例把「不整份替换」这个决定钉住。
func TestApplyHostHotUpdate_DoesNotWipeOtherConfig(t *testing.T) {
	h := &wafenginmodel.HostSafe{}
	h.Host.Code = "c1"
	h.Host.Host = "a.com"
	h.Host.Port = 9113
	h.Host.CaptchaJSON = `{"is_enable_captcha":1}`
	h.Host.IPMode = "proxy"

	// 只带开关字段的记录（其余为零值）
	ApplyHostHotUpdate(h, model.Hosts{GUARD_STATUS: 1, EmergencyMode: 1})

	if h.Host.Code != "c1" || h.Host.Host != "a.com" || h.Host.Port != 9113 {
		t.Fatalf("站点标识被抹掉了: %+v", h.Host)
	}
	if h.Host.CaptchaJSON == "" || h.Host.IPMode != "proxy" {
		t.Fatalf("其余站点配置被抹掉了——热更新只该搬登记过的字段")
	}
}
