package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"strings"
	"time"
)

type WafTamperRuleService struct{}

var WafTamperRuleServiceApp = new(WafTamperRuleService)

// validateUrl 受保护 URL 必须是精确路径：非空、以 / 开头、不含通配符与 query
func validateTamperUrl(url string) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("受保护URL不能为空")
	}
	if !strings.HasPrefix(url, "/") {
		return errors.New("受保护URL需以 / 开头的精确路径，例如 /index.html")
	}
	if strings.Contains(url, "*") {
		return errors.New("受保护URL不支持通配符，请填写精确路径")
	}
	if strings.ContainsAny(url, "?#") {
		return errors.New("受保护URL不能包含参数(?)或锚点(#)")
	}
	return nil
}

func (receiver *WafTamperRuleService) AddApi(req request.WafTamperRuleAddReq) error {
	if err := validateTamperUrl(req.Url); err != nil {
		return err
	}
	var bean = &model.TamperRule{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:       req.HostCode,
		Url:            strings.TrimSpace(req.Url),
		RuleName:       req.RuleName,
		IsEnable:       req.IsEnable,
		IgnoreQuery:    req.IgnoreQuery,
		BaselineStatus: 0, // 待学习
		Remarks:        req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafTamperRuleService) CheckIsExistApi(req request.WafTamperRuleAddReq) int {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("host_code=? and url=?", req.HostCode, strings.TrimSpace(req.Url)).Count(&total)
	return int(total)
}

func (receiver *WafTamperRuleService) ModifyApi(req request.WafTamperRuleEditReq) error {
	if err := validateTamperUrl(req.Url); err != nil {
		return err
	}
	// 同站点同 URL 唯一（排除自身）
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("host_code=? and url=? and id<>?", req.HostCode, strings.TrimSpace(req.Url), req.Id).Count(&total)
	if total > 0 {
		return errors.New("同站点下该URL的防篡改规则已存在")
	}

	// 若 URL 变化则基线作废，需重新学习
	var old model.TamperRule
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&old)

	beanMap := map[string]interface{}{
		"HostCode":    req.HostCode,
		"Url":         strings.TrimSpace(req.Url),
		"RuleName":    req.RuleName,
		"IsEnable":    req.IsEnable,
		"IgnoreQuery": req.IgnoreQuery,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if old.Id != "" && old.Url != strings.TrimSpace(req.Url) {
		beanMap["BaselineStatus"] = 0
		beanMap["BaselineHash"] = ""
		beanMap["BaselineContent"] = []byte{}
		beanMap["BaselineMsg"] = "URL已变更，待重新学习"
	}
	err := global.GWAF_LOCAL_DB.Model(model.TamperRule{}).Where("id = ?", req.Id).Updates(beanMap).Error
	return err
}

// RelearnApi 触发重新学习：清空基线状态并即时后端自抓重建（无后端则保持惰性，下次访问再学）
func (receiver *WafTamperRuleService) RelearnApi(req request.WafTamperRuleRelearnReq) error {
	beanMap := map[string]interface{}{
		"BaselineStatus":  0,
		"BaselineHash":    "",
		"BaselineContent": []byte{},
		"ContentSize":     0,
		"BaselineMsg":     "已标记重新学习",
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(model.TamperRule{}).Where("id = ?", req.Id).Updates(beanMap).Error; err != nil {
		return err
	}
	// 即时触发后端自抓重建基线
	var rule model.TamperRule
	global.GWAF_LOCAL_DB.Omit("baseline_content").Where("id=?", req.Id).Find(&rule)
	if rule.HostCode != "" {
		receiver.backgroundRecapture(rule.HostCode, []string{req.Id})
	}
	return nil
}

// RelearnBatchApi 批量/整站重新学习：Ids 为空则该站点全部规则重新学习（限定在 HostCode 内，防误伤其它站点）
func (receiver *WafTamperRuleService) RelearnBatchApi(req request.WafTamperRuleRelearnBatchReq) error {
	if strings.TrimSpace(req.HostCode) == "" {
		return errors.New("缺少站点标识")
	}
	beanMap := map[string]interface{}{
		"BaselineStatus":  0,
		"BaselineHash":    "",
		"BaselineContent": []byte{},
		"ContentSize":     0,
		"BaselineMsg":     "已标记重新学习",
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	db := global.GWAF_LOCAL_DB.Model(model.TamperRule{}).Where("host_code = ?", req.HostCode)
	if len(req.Ids) > 0 {
		db = db.Where("id in ?", req.Ids)
	}
	if err := db.Updates(beanMap).Error; err != nil {
		return err
	}
	// 即时触发后端自抓重建基线（后台限并发）
	receiver.backgroundRecapture(req.HostCode, req.Ids)
	return nil
}

// DelBatchApi 批量删除受保护 URL（限定在 HostCode 内），返回删除条数
func (receiver *WafTamperRuleService) DelBatchApi(req request.WafTamperRuleDelBatchReq) (int64, error) {
	if strings.TrimSpace(req.HostCode) == "" {
		return 0, errors.New("缺少站点标识")
	}
	if len(req.Ids) == 0 {
		return 0, nil
	}
	res := global.GWAF_LOCAL_DB.Where("host_code=? and id in ?", req.HostCode, req.Ids).Delete(&model.TamperRule{})
	return res.RowsAffected, res.Error
}

// AddBatchApi 批量新增受保护 URL：逐条校验 + 跳过已存在，返回新增/跳过数
func (receiver *WafTamperRuleService) AddBatchApi(req request.WafTamperRuleAddBatchReq) (int, int, error) {
	if strings.TrimSpace(req.HostCode) == "" {
		return 0, 0, errors.New("缺少站点标识")
	}
	added, skipped := 0, 0
	for _, rawUrl := range req.Urls {
		u := strings.TrimSpace(rawUrl)
		if u == "" {
			continue
		}
		if err := validateTamperUrl(u); err != nil {
			skipped++
			continue
		}
		var total int64 = 0
		global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("host_code=? and url=?", req.HostCode, u).Count(&total)
		if total > 0 {
			skipped++
			continue
		}
		bean := &model.TamperRule{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			HostCode:       req.HostCode,
			Url:            u,
			IsEnable:       req.IsEnable,
			IgnoreQuery:    req.IgnoreQuery,
			BaselineStatus: 0,
		}
		if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
			return added, skipped, err
		}
		added++
	}
	return added, skipped, nil
}

func (receiver *WafTamperRuleService) GetDetailApi(req request.WafTamperRuleDetailReq) model.TamperRule {
	var bean model.TamperRule
	// 列表/详情不带大 blob，避免加载慢
	global.GWAF_LOCAL_DB.Omit("baseline_content").Where("id=?", req.Id).Find(&bean)
	return bean
}

func (receiver *WafTamperRuleService) GetDetailByIdApi(id string) model.TamperRule {
	var bean model.TamperRule
	global.GWAF_LOCAL_DB.Omit("baseline_content").Where("id=?", id).Find(&bean)
	return bean
}

// GetBaselineApi 按需取基线正文（含 blob），供“查看基线”弹窗
func (receiver *WafTamperRuleService) GetBaselineApi(id string) model.TamperRule {
	var bean model.TamperRule
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}

// tamperOrderCols 允许排序的列白名单（防 SQL 注入：order by 只能取这里的值）
var tamperOrderCols = map[string]string{
	"url":             "url",
	"rule_name":       "rule_name",
	"is_enable":       "is_enable",
	"ignore_query":    "ignore_query",
	"baseline_status": "baseline_status",
	"content_size":    "content_size",
	"tamper_count":    "tamper_count",
	"create_time":     "create_time",
}

func (receiver *WafTamperRuleService) GetListApi(req request.WafTamperRuleSearchReq) ([]model.TamperRule, int64, error) {
	var list []model.TamperRule
	var total int64 = 0

	// 动态过滤条件（空/ nil 不过滤）
	var conds []string
	var vals []interface{}
	if len(req.HostCode) > 0 {
		conds = append(conds, "host_code=?")
		vals = append(vals, req.HostCode)
	}
	if s := strings.TrimSpace(req.Url); s != "" {
		conds = append(conds, "url like ?")
		vals = append(vals, "%"+s+"%")
	}
	if s := strings.TrimSpace(req.RuleName); s != "" {
		conds = append(conds, "rule_name like ?")
		vals = append(vals, "%"+s+"%")
	}
	if req.IsEnable != nil {
		conds = append(conds, "is_enable=?")
		vals = append(vals, *req.IsEnable)
	}
	if req.IgnoreQuery != nil {
		conds = append(conds, "ignore_query=?")
		vals = append(vals, *req.IgnoreQuery)
	}
	if req.BaselineStatus != nil {
		conds = append(conds, "baseline_status=?")
		vals = append(vals, *req.BaselineStatus)
	}
	whereStr := strings.Join(conds, " and ")

	// 排序：列走白名单，方向仅 asc/desc，默认按创建时间倒序
	order := "create_time desc"
	if col, ok := tamperOrderCols[req.OrderKey]; ok {
		dir := "asc"
		if strings.EqualFold(req.OrderDir, "desc") {
			dir = "desc"
		}
		order = col + " " + dir
	}

	// Omit baseline_content：列表绝不携带大 blob
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Omit("baseline_content").Where(whereStr, vals...).Order(order).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where(whereStr, vals...).Count(&total)

	return list, total, nil
}

func (receiver *WafTamperRuleService) DelApi(req request.WafTamperRuleDelReq) error {
	var bean model.TamperRule
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.TamperRule{}).Error
	return err
}
