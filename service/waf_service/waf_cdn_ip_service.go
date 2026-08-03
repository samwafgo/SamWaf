package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafenginecore/clientip"
	"SamWaf/wafenginecore/ipset"
	"SamWaf/wafsec"
	"SamWaf/waftask/threatip"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WafCDNIPService CDN 厂商回源段中心库服务。
//
// 职责：统一拉取/持久化各 CDN 厂商回源 IP 段(公开列表 Tier A 匿名拉取；EdgeOne/阿里云走认证 API)，
// 编译为 MatchSet 供业务侧"真实IP来源=cdn_preset"与管理端"可信代理"做严格来源校验。
//
// 原则：
//   - 一处存(cdn_provider 表) → 处处引用读最新，站点/管理端不各自维护。
//   - AutoFetch 默认关：内置厂商不主动对外拉取；等有站点/管理端引用时前端提示用户去开启并可手动触发一次。
//   - 认证凭证加密落库、API 不回显、整表被 waf_sql_query 封禁。
type WafCDNIPService struct{}

var WafCDNIPServiceApp = new(WafCDNIPService)

// CDNProviderView 厂商列表视图：合并代码内元数据 + 库内运行态(脱敏，绝不含明文凭证)
type CDNProviderView struct {
	Provider       string `json:"provider"`
	Name           string `json:"name"`
	Header         string `json:"header"`
	Tier           string `json:"tier"`
	FetchKind      string `json:"fetch_kind"`
	NeedCredential bool   `json:"need_credential"` // 认证型厂商(需填密钥)
	HasCredential  bool   `json:"has_credential"`  // 是否已配置凭证(不回显具体值)
	AutoFetch      int    `json:"auto_fetch"`
	IntervalHour   int    `json:"interval_hour"`
	Count          int    `json:"count"`
	Source         string `json:"source"`
	LastSyncAt     int64  `json:"last_sync_at"`
	LastStatus     string `json:"last_status"`
	InUse          bool   `json:"in_use"`      // 是否被站点/管理端引用
	ExtraParam     string `json:"extra_param"` // 非密参数(region/zone_id)
}

// ---------------- 拉取与落地 ----------------

// fetchProviderCIDRs 按厂商拉取方式取回源段 CIDR 列表，返回(列表, 来源标记, 错误)。
// FetchNone 返回 (nil, "", nil)。认证型从库内解密凭证。
func (r *WafCDNIPService) fetchProviderCIDRs(code string) ([]string, string, error) {
	p, ok := clientip.Providers[code]
	if !ok {
		return nil, "", fmt.Errorf("未知 CDN 厂商: %s", code)
	}
	switch p.FetchKind {
	case clientip.FetchPlain:
		var ips []string
		for _, url := range p.RangeURLs {
			raw, err := threatip.Fetch(url)
			if err != nil {
				return nil, "", fmt.Errorf("拉取 %s 回源段失败: %v", p.Name, err)
			}
			res, _ := threatip.ParseByType(model.ThreatParserCIDROnly, strings.NewReader(string(raw)), 0)
			ips = append(ips, res.IPs...)
		}
		return ips, model.CDNSourceAutoPublic, nil
	case clientip.FetchFastlyJSON:
		raw, err := threatip.Fetch(p.RangeURLs[0])
		if err != nil {
			return nil, "", fmt.Errorf("拉取 Fastly 回源段失败: %v", err)
		}
		ips, err := parseFastlyJSON(raw)
		return ips, model.CDNSourceAutoPublic, err
	case clientip.FetchAWSJSON:
		raw, err := threatip.Fetch(p.RangeURLs[0])
		if err != nil {
			return nil, "", fmt.Errorf("拉取 CloudFront 回源段失败: %v", err)
		}
		ips, err := parseAWSCloudFrontJSON(raw)
		return ips, model.CDNSourceAutoPublic, err
	case clientip.FetchTencent:
		row := r.getRow(code)
		if row == nil || strings.TrimSpace(row.SecretId) == "" {
			return nil, "", fmt.Errorf("腾讯云凭证未配置，无法拉取 EdgeOne 回源段")
		}
		ips, err := fetchTencentEdgeOneCIDRs(decCred(row.SecretId), decCred(row.SecretKey), row.ExtraParam)
		return ips, model.CDNSourceAuthAPI, err
	case clientip.FetchAliyun:
		row := r.getRow(code)
		if row == nil || strings.TrimSpace(row.SecretId) == "" {
			return nil, "", fmt.Errorf("阿里云凭证未配置，无法拉取回源段")
		}
		ips, err := fetchAliyunCIDRs(decCred(row.SecretId), decCred(row.SecretKey), row.ExtraParam)
		return ips, model.CDNSourceAuthAPI, err
	default:
		return nil, "", nil // FetchNone
	}
}

// RefreshProvider 拉取某厂商回源段 → 落中心库 → 发布内存匹配集。手动触发或定时到期时调用。
func (r *WafCDNIPService) RefreshProvider(code string) error {
	ips, source, err := r.fetchProviderCIDRs(code)
	if err != nil {
		r.markStatus(code, "拉取失败: "+err.Error(), -1)
		return err
	}
	if ips == nil && source == "" {
		return nil // 无自动拉取方式(FetchNone)
	}
	if len(ips) == 0 {
		msg := "回源段为空，跳过发布(避免误将全部来源判为不可信)"
		r.markStatus(code, msg, -1)
		return fmt.Errorf("%s %s", code, msg)
	}
	if err := r.saveSnapshot(code, ips, source); err != nil {
		r.markStatus(code, "落库失败: "+err.Error(), -1)
		return err
	}
	clientip.SetProviderRanges(code, ipset.BuildMatchSet(ips))
	r.markStatus(code, fmt.Sprintf("ok(%d条)", len(ips)), len(ips))
	zlog.Info("CDN 回源段已刷新", "provider", code, "count", len(ips), "source", source)
	return nil
}

// GetProviderCIDRs 返回某厂商回源段 CIDR 列表并顺带刷新缓存(供管理端"快捷填充"旧入口保留)。
func (r *WafCDNIPService) GetProviderCIDRs(code string) ([]string, error) {
	ips, source, err := r.fetchProviderCIDRs(code)
	if err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		_ = r.saveSnapshot(code, ips, source)
		clientip.SetProviderRanges(code, ipset.BuildMatchSet(ips))
	}
	return ips, nil
}

// RestoreAllOnStartup 进程启动重放：把库内已存的各厂商回源段解压重新发布到内存匹配集(不重新对外拉取)。
func (r *WafCDNIPService) RestoreAllOnStartup() {
	var rows []model.CDNProvider
	global.GWAF_LOCAL_DB.Where("count > 0").Find(&rows)
	for _, row := range rows {
		ips, err := threatip.DecodeSnapshot(row.Payload)
		if err != nil || len(ips) == 0 {
			continue
		}
		clientip.SetProviderRanges(row.Provider, ipset.BuildMatchSet(ips))
	}
	if len(rows) > 0 {
		zlog.Info("CDN 回源段中心库已重放", "providers", len(rows))
	}
}

// SyncAllDue 定时任务：遍历已开启自动拉取且到期的厂商，逐个刷新。
func (r *WafCDNIPService) SyncAllDue() {
	var rows []model.CDNProvider
	global.GWAF_LOCAL_DB.Where("auto_fetch = 1").Find(&rows)
	now := time.Now().Unix()
	for _, row := range rows {
		interval := int64(defaultInt(row.IntervalHour, 24)) * 3600
		if row.LastSyncAt > 0 && now-row.LastSyncAt < interval {
			continue // 未到期
		}
		if err := r.RefreshProvider(row.Provider); err != nil {
			zlog.Warn("CDN 回源段定时刷新失败", "provider", row.Provider, "error", err.Error())
		}
	}
}

// RefreshProvidersInUse 兼容旧入口：刷新"被引用且已开启自动拉取"的厂商(启动流程调用)。
// 现在仅刷新 AutoFetch=1 的厂商，避免默认对外拉取。
func (r *WafCDNIPService) RefreshProvidersInUse() {
	var rows []model.CDNProvider
	global.GWAF_LOCAL_DB.Where("auto_fetch = 1").Find(&rows)
	for _, row := range rows {
		if !r.providerInUse(row.Provider) {
			continue
		}
		if err := r.RefreshProvider(row.Provider); err != nil {
			zlog.Warn("刷新 CDN 回源段失败", "provider", row.Provider, "error", err.Error())
		}
	}
}

// ---------------- 配置(开关/周期/凭证) ----------------

// SetAutoFetch 开/关某厂商自动拉取并可设周期。enable=1 且首次开启时立即拉取一次。
func (r *WafCDNIPService) SetAutoFetch(code string, enable, intervalHour int) error {
	if _, ok := clientip.Providers[code]; !ok {
		return fmt.Errorf("未知 CDN 厂商: %s", code)
	}
	row := r.ensureRow(code)
	updates := map[string]interface{}{
		"AutoFetch":   enable,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if intervalHour > 0 {
		updates["IntervalHour"] = intervalHour
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.CDNProvider{}).Where("id = ?", row.Id).Updates(updates).Error; err != nil {
		return err
	}
	if enable == 1 {
		// 首次开启立即拉取一次(认证型若无凭证会返回错误，前端展示状态)
		go func() {
			if err := r.RefreshProvider(code); err != nil {
				zlog.Warn("开启自动拉取后首次刷新失败", "provider", code, "error", err.Error())
			}
		}()
	}
	return nil
}

// SetCredential 保存认证型厂商凭证(加密落库，绝不回显)。secretId/secretKey 为空则清空。
func (r *WafCDNIPService) SetCredential(code, secretId, secretKey, extraParam string) error {
	p, ok := clientip.Providers[code]
	if !ok {
		return fmt.Errorf("未知 CDN 厂商: %s", code)
	}
	if p.Tier != clientip.TierAuth {
		return fmt.Errorf("%s 非认证型厂商，无需配置凭证", p.Name)
	}
	row := r.ensureRow(code)
	updates := map[string]interface{}{
		"ExtraParam":  extraParam,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	// 空值=不改动(避免前端不回显导致误清空)；显式清空用特殊标记另行处理，这里留空即保持原值
	if strings.TrimSpace(secretId) != "" {
		updates["SecretId"] = encCred(secretId)
	}
	if strings.TrimSpace(secretKey) != "" {
		updates["SecretKey"] = encCred(secretKey)
	}
	return global.GWAF_LOCAL_DB.Model(&model.CDNProvider{}).Where("id = ?", row.Id).Updates(updates).Error
}

// ClearCredential 清空某厂商凭证
func (r *WafCDNIPService) ClearCredential(code string) error {
	row := r.getRow(code)
	if row == nil {
		return nil
	}
	return global.GWAF_LOCAL_DB.Model(&model.CDNProvider{}).Where("id = ?", row.Id).Updates(map[string]interface{}{
		"SecretId":    "",
		"SecretKey":   "",
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error
}

// ---------------- 查询(列表/详情/浏览) ----------------

// GetProviderList 返回所有内置厂商的合并视图(元数据 + 运行态，脱敏)。
func (r *WafCDNIPService) GetProviderList() []CDNProviderView {
	rows := map[string]model.CDNProvider{}
	var list []model.CDNProvider
	global.GWAF_LOCAL_DB.Find(&list)
	for _, row := range list {
		rows[row.Provider] = row
	}
	// 稳定顺序
	order := []string{"cloudflare", "fastly", "cloudfront", "edgeone", "aliyun", "akamai"}
	out := make([]CDNProviderView, 0, len(order))
	for _, code := range order {
		p, ok := clientip.Providers[code]
		if !ok {
			continue
		}
		v := CDNProviderView{
			Provider:       p.Code,
			Name:           p.Name,
			Header:         p.Header,
			Tier:           p.Tier,
			FetchKind:      p.FetchKind,
			NeedCredential: p.Tier == clientip.TierAuth,
			InUse:          r.providerInUse(code),
		}
		if row, has := rows[code]; has {
			v.AutoFetch = row.AutoFetch
			v.IntervalHour = row.IntervalHour
			v.Count = row.Count
			v.Source = row.Source
			v.LastSyncAt = row.LastSyncAt
			v.LastStatus = row.LastStatus
			v.ExtraParam = row.ExtraParam
			v.HasCredential = strings.TrimSpace(row.SecretId) != ""
		}
		out = append(out, v)
	}
	return out
}

// GetProviderInfo 返回单厂商视图(供 host 表单/管理端只读展示)。
func (r *WafCDNIPService) GetProviderInfo(code string) *CDNProviderView {
	for _, v := range r.GetProviderList() {
		if v.Provider == code {
			vv := v
			return &vv
		}
	}
	return nil
}

// GetProviderRanges 分页浏览某厂商回源段 CIDR(只读)。keyword 子串过滤。
func (r *WafCDNIPService) GetProviderRanges(code, keyword string, pageIndex, pageSize int) ([]string, int64) {
	row := r.getRow(code)
	if row == nil {
		return []string{}, 0
	}
	ips, _ := threatip.DecodeSnapshot(row.Payload)
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		filtered := make([]string, 0, len(ips))
		for _, ip := range ips {
			if strings.Contains(ip, keyword) {
				filtered = append(filtered, ip)
			}
		}
		ips = filtered
	}
	total := int64(len(ips))
	if pageIndex < 1 {
		pageIndex = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	start := (pageIndex - 1) * pageSize
	if start >= len(ips) {
		return []string{}, total
	}
	end := start + pageSize
	if end > len(ips) {
		end = len(ips)
	}
	return ips[start:end], total
}

// ---------------- 内部辅助 ----------------

// getRow 载入某厂商库行(无则 nil)
func (r *WafCDNIPService) getRow(code string) *model.CDNProvider {
	var row model.CDNProvider
	if err := global.GWAF_LOCAL_DB.Where("provider = ?", code).First(&row).Error; err != nil {
		return nil
	}
	return &row
}

// ensureRow 取或建某厂商库行(建时 AutoFetch=0 默认关)
func (r *WafCDNIPService) ensureRow(code string) *model.CDNProvider {
	if row := r.getRow(code); row != nil {
		return row
	}
	row := &model.CDNProvider{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Provider:     code,
		AutoFetch:    0,
		IntervalHour: 24,
	}
	global.GWAF_LOCAL_DB.Create(row)
	return row
}

// saveSnapshot 持久化某厂商最新回源段快照(保留配置字段不动)
func (r *WafCDNIPService) saveSnapshot(code string, ips []string, source string) error {
	payload, sha, count, err := threatip.EncodeSnapshot(ips)
	if err != nil {
		return err
	}
	row := r.ensureRow(code)
	return global.GWAF_LOCAL_DB.Model(&model.CDNProvider{}).Where("id = ?", row.Id).Updates(map[string]interface{}{
		"Count":       count,
		"Payload":     payload,
		"Sha256":      sha,
		"Source":      source,
		"LastSyncAt":  time.Now().Unix(),
		"LastStatus":  "ok",
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error
}

// markStatus 更新某厂商拉取状态(count<0 表示只更状态不改条数)
func (r *WafCDNIPService) markStatus(code, status string, count int) {
	row := r.ensureRow(code)
	updates := map[string]interface{}{
		"LastStatus":  truncateStatus(status),
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if count >= 0 {
		updates["Count"] = count
		updates["LastSyncAt"] = time.Now().Unix()
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.CDNProvider{}).Where("id = ?", row.Id).Updates(updates).Error; err != nil {
		zlog.Warn("CDN 厂商状态回写失败", "provider", code, "error", err.Error())
	}
}

// providerInUse 判断厂商是否被站点(cdn_preset)或管理端引用
func (r *WafCDNIPService) providerInUse(code string) bool {
	if code == "" {
		return false
	}
	if global.GCONFIG_MANAGE_CDN_PROVIDER == code {
		return true
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("ip_source_mode = ? AND cdn_provider = ?", "cdn_preset", code).Count(&cnt)
	return cnt > 0
}

// encCred/decCred 凭证 AES 加解密(复用通讯密钥；空值原样返回)
func encCred(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	c, err := wafsec.AesEncrypt([]byte(s), global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		zlog.Error("CDN 凭证加密失败", err.Error())
		return ""
	}
	return c
}

func decCred(c string) string {
	if strings.TrimSpace(c) == "" {
		return ""
	}
	b, err := wafsec.AesDecrypt(c, global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		zlog.Error("CDN 凭证解密失败", err.Error())
		return ""
	}
	return string(b)
}

// parseFastlyJSON 解析 Fastly public-ip-list：{"addresses":[...],"ipv6_addresses":[...]}
func parseFastlyJSON(raw []byte) ([]string, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 Fastly JSON 失败: %v", err)
	}
	return append(doc.Addresses, doc.IPv6Addresses...), nil
}

// parseAWSCloudFrontJSON 解析 AWS ip-ranges.json，仅取 service=CLOUDFRONT_ORIGIN_FACING 的段
func parseAWSCloudFrontJSON(raw []byte) ([]string, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析 AWS ip-ranges JSON 失败: %v", err)
	}
	const svc = "CLOUDFRONT_ORIGIN_FACING"
	var ips []string
	for _, p := range doc.Prefixes {
		if p.Service == svc {
			ips = append(ips, p.IPPrefix)
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if p.Service == svc {
			ips = append(ips, p.IPv6Prefix)
		}
	}
	return ips, nil
}
