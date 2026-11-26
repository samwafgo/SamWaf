package waf_service

import (
	"SamWaf/model"
	"SamWaf/utils"
	"encoding/json"
	"fmt"
)

// StaticRootCheck 保存网站或路径路由前对静态目录的判定结果。
// 只有新增或改动的静态目录才按允许目录校验（Checked=true），已保存且未改动的配置原样放行。
type StaticRootCheck struct {
	Checked bool
	OldPath string
	NewPath string
	Err     error
}

// CheckHostStaticSiteChange 判定网站的静态站点配置。oldJSON 为空表示新增。
func CheckHostStaticSiteChange(newJSON, oldJSON string) StaticRootCheck {
	newCfg, ok := parseStaticSiteConfig(newJSON)
	if !ok || newCfg.IsEnableStaticSite != 1 {
		return StaticRootCheck{}
	}
	chk := StaticRootCheck{NewPath: newCfg.StaticSitePath}
	if oldCfg, ok := parseStaticSiteConfig(oldJSON); ok {
		chk.OldPath = oldCfg.StaticSitePath
		if oldCfg.IsEnableStaticSite == 1 && utils.SameStaticRoot(oldCfg.StaticSitePath, newCfg.StaticSitePath) {
			return chk
		}
	}
	chk.Checked = true
	_, chk.Err = utils.ValidateStaticRoot(newCfg.StaticSitePath)
	return chk
}

// CheckPathRuleStaticChange 判定路径路由的静态目录。old 为 nil 表示新增。
func CheckPathRuleStaticChange(targetType int, staticRoot string, old *model.HostPathRule) StaticRootCheck {
	if targetType != model.PathRuleTargetStatic {
		return StaticRootCheck{}
	}
	chk := StaticRootCheck{NewPath: staticRoot}
	if old != nil && old.Id != "" {
		chk.OldPath = old.StaticRoot
		if old.TargetType == model.PathRuleTargetStatic && utils.SameStaticRoot(old.StaticRoot, staticRoot) {
			return chk
		}
	}
	chk.Checked = true
	_, chk.Err = utils.ValidateStaticRoot(staticRoot)
	return chk
}

func parseStaticSiteConfig(raw string) (model.StaticSiteConfig, bool) {
	var cfg model.StaticSiteConfig
	if raw == "" {
		return cfg, false
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, false
	}
	return cfg, true
}

// StaticRootAuditTarget 静态目录变更审计的对象信息。
type StaticRootAuditTarget struct {
	Actor      string
	ClientIP   string
	ObjectType string
	ObjectID   string
	HostCode   string
	Host       string
	Label      string // 展示用名称，如「网站 a.com」「路径路由 /static」
}

// WriteStaticRootChange 记一条静态目录变更审计。只记经过校验的变更（chk.Checked）。
// saveErr 为保存阶段的其他错误，校验通过但保存失败时不记成功。
func (receiver *WafSecurityAuditService) WriteStaticRootChange(target StaticRootAuditTarget, chk StaticRootCheck, saveErr error) {
	if !chk.Checked {
		return
	}
	result, msg := model.AccessAuditOK, fmt.Sprintf("%s 静态目录 %q → %q 已保存", target.Label, chk.OldPath, chk.NewPath)
	switch {
	case chk.Err != nil:
		result, msg = model.AccessAuditFail, fmt.Sprintf("%s 静态目录 %q → %q 未保存：%s", target.Label, chk.OldPath, chk.NewPath, chk.Err.Error())
	case saveErr != nil:
		result, msg = model.AccessAuditFail, fmt.Sprintf("%s 静态目录 %q → %q 未保存：保存失败", target.Label, chk.OldPath, chk.NewPath)
	}
	receiver.Write(AuditEntry{
		Event:       model.AuditEventConfigStaticRootChange,
		AccountName: target.Actor,
		ClientIP:    target.ClientIP,
		Host:        target.Host,
		HostCode:    target.HostCode,
		ObjectType:  target.ObjectType,
		ObjectID:    target.ObjectID,
		Result:      result,
		Message:     msg,
	})
}
