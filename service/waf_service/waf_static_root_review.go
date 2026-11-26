package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 启动巡检的发现类型。目录类沿用 utils.StaticRoot* 分类。
const (
	staticReviewListReduced = "list_reduced" // 敏感清单比默认值少了条目，或允许扩展名比默认值多了条目
)

// staticRootFinding 一条巡检发现。
type staticRootFinding struct {
	ObjectType string
	ObjectID   string
	HostCode   string
	Host       string
	Kind       string
	Path       string
	Message    string
	Digest     string // 参与指纹的发现内容
}

func (f staticRootFinding) fingerprint() string {
	sum := sha256.Sum256([]byte(f.ObjectType + "\x00" + f.ObjectID + "\x00" + f.Path + "\x00" + f.Kind + "\x00" + f.Digest))
	return hex.EncodeToString(sum[:])
}

// ReviewStaticRoots 启动巡检：核对启用中的静态站点与静态路径路由，不合允许目录策略或清单偏离默认值的写入安全审计。
// 同一对象、目录与发现已记过的不重复记录。只记录，不改配置、不影响服务。
func ReviewStaticRoots() {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("静态目录巡检异常", r)
		}
	}()
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil {
		return
	}
	written, err := reviewStaticRoots(global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB)
	if err != nil {
		zlog.Error("静态目录巡检未完成", err)
	}
	if written > 0 {
		zlog.Info(fmt.Sprintf("静态目录巡检新增 %d 条待核对记录，详见安全审计「静态目录巡检」", written))
	}
}

func reviewStaticRoots(core, audit *gorm.DB) (int64, error) {
	var hosts []model.Hosts
	if err := core.Select("code", "host", "static_site_json").Find(&hosts).Error; err != nil {
		return 0, err
	}
	var rules []model.HostPathRule
	if err := core.Select("id", "host_code", "path", "static_root").Where("target_type = ?", model.PathRuleTargetStatic).Find(&rules).Error; err != nil {
		return 0, err
	}
	var written int64
	for _, f := range collectStaticRootFindings(hosts, rules) {
		bean := newSecurityAuditLog(AuditEntry{
			Event: model.AuditEventConfigStaticRootReview, AccountName: "system",
			Host: f.Host, HostCode: f.HostCode, ObjectType: f.ObjectType, ObjectID: f.ObjectID,
			Fingerprint: f.fingerprint(), Result: model.AccessAuditFail, Message: f.Message,
		}, time.Now())
		// 相同租户和发现使用相同主键，两个 Worker 同时启动也只留一条。
		key := sha256.Sum256([]byte(bean.Tenant_ID + "\x00" + bean.USER_CODE + "\x00" + bean.Event + "\x00" + bean.Fingerprint))
		bean.Id = hex.EncodeToString(key[:])
		result := audit.Clauses(clause.OnConflict{DoNothing: true}).Create(&bean)
		if result.Error != nil {
			return written, result.Error
		}
		written += result.RowsAffected
	}
	return written, nil
}

// collectStaticRootFindings 计算巡检发现，不访问数据库。
func collectStaticRootFindings(hosts []model.Hosts, rules []model.HostPathRule) []staticRootFinding {
	var out []staticRootFinding
	hostByCode := make(map[string]model.Hosts, len(hosts))
	staticHosts := make(map[string]bool)
	for _, h := range hosts {
		hostByCode[h.Code] = h
		cfg, ok := parseStaticSiteConfig(h.StaticSiteJSON)
		if !ok || cfg.IsEnableStaticSite != 1 {
			continue
		}
		staticHosts[h.Code] = true
		if f, bad := staticDirFinding(model.AuditObjectTypeHost, h.Code, h.Code, h.Host, "网站 "+h.Host, cfg.StaticSitePath); bad {
			out = append(out, f)
		}
	}
	for _, r := range rules {
		host := hostByCode[r.HostCode].Host
		staticHosts[r.HostCode] = true
		if f, bad := staticDirFinding(model.AuditObjectTypePathRule, r.Id, r.HostCode, host, "网站 "+host+" 路径路由 "+r.Path, r.StaticRoot); bad {
			out = append(out, f)
		}
	}
	// 清单在网站上配置，静态站点与该网站的静态路径路由共用
	for code := range staticHosts {
		h, ok := hostByCode[code]
		if !ok {
			continue
		}
		cfg, _ := parseStaticSiteConfig(h.StaticSiteJSON)
		if f, bad := staticListFinding(h, cfg); bad {
			out = append(out, f)
		}
	}
	return out
}

func staticDirFinding(objectType, objectID, hostCode, host, label, dir string) (staticRootFinding, bool) {
	_, err := utils.ValidateStaticRoot(dir)
	if err == nil {
		return staticRootFinding{}, false
	}
	kind := utils.StaticRootErrorCode(err)
	if kind == "" {
		kind = utils.StaticRootInvalid
	}
	return staticRootFinding{
		ObjectType: objectType,
		ObjectID:   objectID,
		HostCode:   hostCode,
		Host:       host,
		Kind:       kind,
		Path:       strings.TrimSpace(dir),
		Message:    fmt.Sprintf("%s 静态目录 %q 待核对：%s", label, dir, err.Error()),
	}, true
}

func staticListFinding(h model.Hosts, cfg model.StaticSiteConfig) (staticRootFinding, bool) {
	var parts []string
	add := func(name string, items []string) {
		if len(items) > 0 {
			parts = append(parts, fmt.Sprintf("%s %d 项（%s）", name, len(items), strings.Join(items, ",")))
		}
	}
	// 空串时引擎按默认值处理，不算偏离
	if cfg.SensitivePaths != "" {
		add("敏感路径比默认值少", listMissing(model.StaticSiteDefaultSensitivePaths, cfg.SensitivePaths, true))
	}
	if cfg.SensitiveExtensions != "" {
		add("敏感扩展名比默认值少", listMissingExt(model.StaticSiteDefaultSensitiveExtensions, cfg.SensitiveExtensions))
	}
	if cfg.SensitivePatterns != "" {
		add("敏感文件名模式比默认值少", listMissing(model.StaticSiteDefaultSensitivePatterns, cfg.SensitivePatterns, false))
	}
	if cfg.AllowedExtensions != "" {
		add("允许扩展名比默认值多", listMissingExt(cfg.AllowedExtensions, model.StaticSiteDefaultAllowedExtensions))
	}
	if len(parts) == 0 {
		return staticRootFinding{}, false
	}
	detail := strings.Join(parts, "；")
	return staticRootFinding{
		ObjectType: model.AuditObjectTypeHost,
		ObjectID:   h.Code,
		HostCode:   h.Code,
		Host:       h.Host,
		Kind:       staticReviewListReduced,
		Path:       cfg.StaticSitePath,
		Digest:     detail,
		Message:    fmt.Sprintf("网站 %s 静态文件清单偏离默认值：%s", h.Host, detail),
	}, true
}

// listMissingExt 扩展名清单比对：忽略大小写与开头的点（历史默认值里有写 "key" 的）。
func listMissingExt(want, have string) []string {
	trim := func(s string) string {
		return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), ".")
	}
	set := make(map[string]bool)
	for _, v := range strings.Split(have, ",") {
		if v = trim(v); v != "" {
			set[v] = true
		}
	}
	var missing []string
	seen := make(map[string]bool)
	for _, v := range strings.Split(want, ",") {
		key := trim(v)
		if key == "" || set[key] || seen[key] {
			continue
		}
		seen[key] = true
		missing = append(missing, strings.TrimSpace(v))
	}
	sort.Strings(missing)
	return missing
}

// listMissing 返回 want 中有、have 中没有的条目（逗号分隔，去空白）。
func listMissing(want, have string, foldCase bool) []string {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		if foldCase {
			s = strings.ToLower(s)
		}
		return s
	}
	set := make(map[string]bool)
	for _, v := range strings.Split(have, ",") {
		if v = norm(v); v != "" {
			set[v] = true
		}
	}
	var missing []string
	seen := make(map[string]bool)
	for _, v := range strings.Split(want, ",") {
		raw := strings.TrimSpace(v)
		key := norm(v)
		if key == "" || set[key] || seen[key] {
			continue
		}
		seen[key] = true
		missing = append(missing, raw)
	}
	sort.Strings(missing)
	return missing
}
