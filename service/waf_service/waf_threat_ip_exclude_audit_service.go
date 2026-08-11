package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"strings"
	"time"
)

// WafThreatIPExcludeAuditService 排除名单操作审计。
//
// 单独一份只增不改的流水：排除条目本身会被删除，删了就查不到"曾经排除过什么"，
// 而排除是主动降低防护的动作，必须能回溯到人和时间。落日志库，随保留策略清理。
type WafThreatIPExcludeAuditService struct{}

var WafThreatIPExcludeAuditApp = new(WafThreatIPExcludeAuditService)

// Write 写一条审计流水。审计失败只记日志、不阻断主流程——
// 不能因为流水写不进去就让用户没法处理误报。
func (r *WafThreatIPExcludeAuditService) Write(rec model.ThreatIPExcludeAudit) {
	if global.GWAF_LOCAL_LOG_DB == nil {
		return
	}
	rec.BaseOrm = baseorm.BaseOrm{
		Id:          uuid.GenUUID(),
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
	if rec.Operator == "" {
		rec.Operator = "unknown"
	}
	if err := global.GWAF_LOCAL_LOG_DB.Create(&rec).Error; err != nil {
		zlog.Error("写威胁情报排除审计失败: " + err.Error())
	}
}

// GetListApi 分页查询审计流水
func (r *WafThreatIPExcludeAuditService) GetListApi(req request.WafThreatIPExcludeAuditSearchReq) ([]model.ThreatIPExcludeAudit, int64, error) {
	var list []model.ThreatIPExcludeAudit
	var total int64
	if global.GWAF_LOCAL_LOG_DB == nil {
		return list, 0, nil
	}
	db := global.GWAF_LOCAL_LOG_DB.Model(&model.ThreatIPExcludeAudit{})
	if v := strings.TrimSpace(req.Entry); v != "" {
		db = db.Where("entry LIKE ?", "%"+v+"%")
	}
	if v := strings.TrimSpace(req.Action); v != "" {
		db = db.Where("action = ?", v)
	}
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := db.Order("create_time DESC").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	return list, total, err
}
