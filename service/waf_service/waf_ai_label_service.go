package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafai"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type WafAILabelService struct{}

var WafAILabelServiceApp = new(WafAILabelService)

// 合法的标记取值
var validMarks = map[string]bool{"normal": true, "attack": true, "ignore": true}

// LabelMarkInfo 标记回显/导出用的精简信息
type LabelMarkInfo struct {
	Mark       string `json:"mark"`
	AttackType string `json:"attack_type"`
}

// MarkApi 新增/更新某条日志的训练标签修正（按 req_uuid 幂等 upsert）。
// 标记时即从日志库读取该请求的训练字段做快照，导出不再受时间/条数条件限制，
// 即使原始日志后续被清理也能产出该样本。
func (receiver *WafAILabelService) MarkApi(req request.WafAILabelMarkReq) error {
	if !validMarks[req.Mark] {
		return errors.New("非法的标记类型")
	}

	// 读取原始日志做快照（标记时日志通常仍存在）
	var wl innerbean.WebLog
	global.GWAF_LOCAL_LOG_DB.
		Select("METHOD", "URL", "RawQuery", "BODY", "POST_FORM", "USER_AGENT", "ACTION", "RULE", "SRC_IP", "HOST_CODE", "LogOnlyMode").
		Where("REQ_UUID = ?", req.ReqUuid).Limit(1).Find(&wl)

	body := wl.BODY
	if body == "" {
		body = wl.POST_FORM
	}
	hostCode := wl.HOST_CODE
	if hostCode == "" {
		hostCode = req.HostCode
	}
	rule := wl.RULE
	if rule == "" {
		rule = req.Rule
	}
	srcIp := wl.SRC_IP
	if srcIp == "" {
		srcIp = req.SrcIp
	}
	url := wl.URL
	if url == "" {
		url = req.Url
	}

	// 解析攻击分类：优先人工指定；为空且标记为攻击时按原始日志自动判定
	attackType := req.AttackType
	if req.Mark == "attack" && attackType == "" {
		if _, at := wafai.WeakLabel(wl.ACTION, wl.RULE, wl.LogOnlyMode); at != "" {
			attackType = at
		} else {
			attackType = "other"
		}
	}

	fields := map[string]interface{}{
		"mark":        req.Mark,
		"attack_type": attackType,
		"rule":        rule,
		"host_code":   hostCode,
		"src_ip":      srcIp,
		"url":         url,
		"method":      strings.ToUpper(wl.METHOD),
		"raw_query":   wl.RawQuery,
		"body":        body,
		"user_agent":  wl.USER_AGENT,
		"update_time": customtype.JsonTime(time.Now()),
	}

	var existing model.WafLogLabelMark
	global.GWAF_LOCAL_DB.Where("req_uuid = ? and tenant_id = ? and user_code = ?",
		req.ReqUuid, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).First(&existing)

	if existing.Id != "" {
		return global.GWAF_LOCAL_DB.Model(&model.WafLogLabelMark{}).Where("id = ?", existing.Id).
			Updates(fields).Error
	}

	bean := &model.WafLogLabelMark{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		REQ_UUID:   req.ReqUuid,
		HOST_CODE:  hostCode,
		Mark:       req.Mark,
		AttackType: attackType,
		RULE:       rule,
		SRC_IP:     srcIp,
		URL:        url,
		METHOD:     strings.ToUpper(wl.METHOD),
		RAW_QUERY:  wl.RawQuery,
		BODY:       body,
		USER_AGENT: wl.USER_AGENT,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

// UnmarkApi 取消某条日志的标记
func (receiver *WafAILabelService) UnmarkApi(reqUuid string) error {
	return global.GWAF_LOCAL_DB.Where("req_uuid = ? and tenant_id = ? and user_code = ?",
		reqUuid, global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Delete(&model.WafLogLabelMark{}).Error
}

// GetMapByUuidsApi 按 req_uuid 批量返回标记（用于日志列表回显）
func (receiver *WafAILabelService) GetMapByUuidsApi(uuids []string) map[string]LabelMarkInfo {
	result := map[string]LabelMarkInfo{}
	if len(uuids) == 0 {
		return result
	}
	var rows []model.WafLogLabelMark
	global.GWAF_LOCAL_DB.Where("tenant_id = ? and user_code = ? and req_uuid in ?",
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, uuids).Find(&rows)
	for _, r := range rows {
		result[r.REQ_UUID] = LabelMarkInfo{Mark: r.Mark, AttackType: r.AttackType}
	}
	return result
}

// GetAllFull 返回当前租户/用户的全部标记（含请求快照），导出时一次性加载，按 req_uuid 索引。
func (receiver *WafAILabelService) GetAllFull() map[string]model.WafLogLabelMark {
	result := map[string]model.WafLogLabelMark{}
	var rows []model.WafLogLabelMark
	global.GWAF_LOCAL_DB.Where("tenant_id = ? and user_code = ?",
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Find(&rows)
	for _, r := range rows {
		result[r.REQ_UUID] = r
	}
	return result
}

// GetMarkStatusMap 轻量返回当前租户/用户全部标记的状态（mark+attack_type），不含请求快照。
// 供标注工作台列表回显与按标记状态过滤使用。
func (receiver *WafAILabelService) GetMarkStatusMap() map[string]LabelMarkInfo {
	result := map[string]LabelMarkInfo{}
	var rows []model.WafLogLabelMark
	global.GWAF_LOCAL_DB.Select("req_uuid", "mark", "attack_type").
		Where("tenant_id = ? and user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE).Find(&rows)
	for _, r := range rows {
		result[r.REQ_UUID] = LabelMarkInfo{Mark: r.Mark, AttackType: r.AttackType}
	}
	return result
}

// ListApi 标注工作台列表：在 AI 命中(ai_score>0)子集上分页查询，并合并人工标记状态。
// 标记数据在 core 库、日志在 log 库（跨库无法 JOIN），故先取本租户标记集合，
// 在内存中做"按标记状态过滤"与逐行回显。
func (receiver *WafAILabelService) ListApi(req request.WafAILabelListReq) response2.WafAILabelList {
	res := response2.WafAILabelList{Rows: []response2.WafAILabelItem{}}
	if global.GWAF_LOCAL_LOG_DB == nil {
		return res
	}

	pageIndex := req.PageIndex
	if pageIndex <= 0 {
		pageIndex = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 20
	}

	markMap := receiver.GetMarkStatusMap()

	// 按标记状态预先算出 IN / NOT IN 的 uuid 集合
	var inUuids []string // 命中即纳入
	useNotIn := false    // true 时改用 NOT IN
	emptyResult := false // 过滤后必然为空，直接返回
	switch req.MarkStatus {
	case "unmarked":
		for u := range markMap {
			inUuids = append(inUuids, u)
		}
		useNotIn = true // 排除全部已标记
	case "marked":
		for u := range markMap {
			inUuids = append(inUuids, u)
		}
		if len(inUuids) == 0 {
			emptyResult = true
		}
	case "normal", "attack", "ignore":
		for u, info := range markMap {
			if info.Mark == req.MarkStatus {
				inUuids = append(inUuids, u)
			}
		}
		if len(inUuids) == 0 {
			emptyResult = true
		}
	}
	if emptyResult {
		return res
	}

	buildQ := func() *gorm.DB {
		q := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where("ai_score > 0")
		if req.StartDay > 0 && req.EndDay > 0 {
			q = q.Where("day between ? and ?", req.StartDay, req.EndDay)
		}
		if req.HostCode != "" {
			q = q.Where("host_code = ?", req.HostCode)
		}
		if req.MinScore > 0 {
			q = q.Where("ai_score >= ?", req.MinScore)
		}
		if len(inUuids) > 0 {
			if useNotIn {
				q = q.Where("req_uuid not in ?", inUuids)
			} else {
				q = q.Where("req_uuid in ?", inUuids)
			}
		}
		return q
	}

	buildQ().Count(&res.Total)

	var rows []innerbean.WebLog
	buildQ().Select("REQ_UUID", "CREATE_TIME", "HOST_CODE", "SRC_IP", "METHOD", "URL",
		"RawQuery", "BODY", "POST_FORM", "USER_AGENT", "AI_SCORE", "RULE", "LogOnlyMode").
		Order("ai_score desc").Order("unix_add_time desc").
		Offset((pageIndex - 1) * pageSize).Limit(pageSize).Find(&rows)

	for i := range rows {
		r := &rows[i]
		body := r.BODY
		if body == "" {
			body = r.POST_FORM
		}
		item := response2.WafAILabelItem{
			ReqUuid:     r.REQ_UUID,
			CreateTime:  r.CREATE_TIME,
			HostCode:    r.HOST_CODE,
			SrcIp:       r.SRC_IP,
			Method:      strings.ToUpper(r.METHOD),
			Url:         r.URL,
			RawQuery:    r.RawQuery,
			Body:        body,
			UserAgent:   r.USER_AGENT,
			AiScore:     r.AI_SCORE,
			Rule:        r.RULE,
			LogOnlyMode: r.LogOnlyMode,
		}
		if info, ok := markMap[r.REQ_UUID]; ok {
			item.Mark = info.Mark
			item.AttackType = info.AttackType
		}
		res.Rows = append(res.Rows, item)
	}
	return res
}

// BatchMarkApi 批量标记：逐条复用 MarkApi（每条独立读取请求快照、按需自动判定分类）。
// 返回成功标记条数。
func (receiver *WafAILabelService) BatchMarkApi(req request.WafAILabelBatchMarkReq) (int, error) {
	if !validMarks[req.Mark] {
		return 0, errors.New("非法的标记类型")
	}
	n := 0
	for _, u := range req.ReqUuids {
		if strings.TrimSpace(u) == "" {
			continue
		}
		if err := receiver.MarkApi(request.WafAILabelMarkReq{
			ReqUuid:    u,
			Mark:       req.Mark,
			AttackType: req.AttackType,
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// BatchUnmarkApi 批量取消标记，返回删除条数。
func (receiver *WafAILabelService) BatchUnmarkApi(uuids []string) (int, error) {
	var clean []string
	for _, u := range uuids {
		if strings.TrimSpace(u) != "" {
			clean = append(clean, u)
		}
	}
	if len(clean) == 0 {
		return 0, nil
	}
	res := global.GWAF_LOCAL_DB.Where("tenant_id = ? and user_code = ? and req_uuid in ?",
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, clean).Delete(&model.WafLogLabelMark{})
	return int(res.RowsAffected), res.Error
}
