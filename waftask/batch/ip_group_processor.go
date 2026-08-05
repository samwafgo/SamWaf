package batch

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/service/waf_service"
	"encoding/json"
	"fmt"
	"time"
)

// IPGroupConfig IP组批量任务额外配置
type IPGroupConfig struct {
	GroupCode string `json:"group_code"` // 目标IP组短码
}

// IPGroupProcessor IP组条目处理器。
//
// 与黑/白名单处理器最大的不同：IP 组是租户级资源，不带 host_code，
// 目标组来自 batch_extra_config.group_code，task.BatchHostCode 在这里完全不参与。
// 生效方式也不同——不下发站点通道消息，而是重建一次 ipset 全局快照，
// 所有引用该组的站点（含全局网站）与自定义规则同时同步。
//
// 处理器实例由每次任务执行单独创建，因此可以安全地持有跨批次状态。
type IPGroupProcessor struct {
	resolved  bool                // 是否已解析过额外配置
	groupCode string              // 解析出的目标组短码
	seen      map[string]struct{} // 覆盖模式下本次源里出现过的全部条目，供收尾时做差集删除
}

// ProcessBatch 处理一批IP
func (p *IPGroupProcessor) ProcessBatch(items []string, task model.BatchTask, progress *BatchProgress) bool {
	if len(items) == 0 {
		return false
	}

	logName := "BatchTask-IPGroupBatch"
	if !p.resolve(task, logName) {
		return false
	}

	zlog.Info(logName, fmt.Sprintf("处理IP组批次，包含 %d 个IP，目标组: %s", len(items), p.groupCode))

	// 覆盖模式下要记住源里出现过的全部条目，收尾时据此删除源中已消失的旧条目
	isOverwrite := task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODOVERWRITE
	if isOverwrite {
		if p.seen == nil {
			p.seen = make(map[string]struct{}, 1024)
		}
		for _, ip := range items {
			p.seen[ip] = struct{}{}
		}
	}

	existMap := p.GetExistingItems(items, task, nil)

	// 追加与覆盖在「入库」这一步行为相同：组内已有的原样保留（不刷备注，避免无谓写放大），
	// 缺的补进来。两者的差别只在收尾要不要删除源中已不存在的条目。
	var toInsert []*model.IPGroupItem
	remark := time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id
	for _, ip := range items {
		if _, exists := existMap[ip]; exists {
			continue
		}
		// 同一批内可能有重复行，先占位避免重复插入
		existMap[ip] = struct{}{}
		toInsert = append(toInsert, &model.IPGroupItem{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			GroupCode: p.groupCode,
			Ip:        ip,
			Remarks:   remark,
		})
	}

	if len(toInsert) == 0 {
		return false
	}

	if err := global.GWAF_LOCAL_DB.CreateInBatches(toInsert, 500).Error; err != nil {
		zlog.Error(logName, "批量插入IP组条目失败: "+err.Error())
		return false
	}
	zlog.Info(logName, fmt.Sprintf("成功插入 %d 条IP组条目", len(toInsert)))
	progress.AddInserted(len(toInsert))
	return true
}

// GetExistingItems 获取组内已存在的条目
func (p *IPGroupProcessor) GetExistingItems(items []string, task model.BatchTask, config interface{}) map[string]interface{} {
	existMap := make(map[string]interface{})
	if p.groupCode == "" {
		return existMap
	}
	var existItems []model.IPGroupItem
	global.GWAF_LOCAL_DB.Where("group_code = ? AND ip IN (?)", p.groupCode, items).Find(&existItems)
	for _, item := range existItems {
		existMap[item.Ip] = item
	}
	return existMap
}

// Finalize 覆盖模式的收尾：删除组内本次源中已不存在的条目，使组内容与源完全一致。
//
// 三道闸门，任何一道不满足都只跳过删除、保留组现状：
//  1. 只有覆盖模式才删（追加模式永远只增不减）
//  2. 源必须被完整读完——半截数据做差集会误删大批合法条目
//  3. 源里至少要有一条有效条目——远程源返回空/404页面时不能把组抹平
//
// 组可能正被白名单引用，误删即全站失去豁免；被黑名单引用则是瞬间放行。宁可少删不可错删。
func (p *IPGroupProcessor) Finalize(task model.BatchTask, progress *BatchProgress, sourceComplete bool) bool {
	if task.BatchExecuteMethod != enums.BATCHTASK_EXECUTEMETHODOVERWRITE {
		return false
	}
	logName := "BatchTask-IPGroupBatch"
	if !p.resolve(task, logName) {
		return false
	}
	if !sourceComplete {
		zlog.Warn(logName, "源未完整读取，跳过覆盖模式的清理，组内原有条目全部保留 组:"+p.groupCode)
		return false
	}
	if len(p.seen) == 0 {
		zlog.Warn(logName, "源中没有任何有效条目，跳过覆盖模式的清理，组内原有条目全部保留 组:"+p.groupCode)
		return false
	}

	var existItems []model.IPGroupItem
	global.GWAF_LOCAL_DB.Where("group_code = ?", p.groupCode).Find(&existItems)

	staleIds := make([]string, 0, 64)
	for i := range existItems {
		if _, ok := p.seen[existItems[i].Ip]; !ok {
			staleIds = append(staleIds, existItems[i].Id)
		}
	}
	if len(staleIds) == 0 {
		return false
	}

	// 分片删除，避免 IN 列表过长撑爆 SQL 语句长度限制
	deleted := 0
	const chunkSize = 500
	for start := 0; start < len(staleIds); start += chunkSize {
		end := start + chunkSize
		if end > len(staleIds) {
			end = len(staleIds)
		}
		if err := global.GWAF_LOCAL_DB.Where("id IN ?", staleIds[start:end]).Delete(&model.IPGroupItem{}).Error; err != nil {
			zlog.Error(logName, "覆盖模式清理IP组条目失败: "+err.Error())
			// 已删掉的部分仍需重建匹配集，所以返回 deleted > 0 而不是 false
			return deleted > 0
		}
		deleted += end - start
	}
	zlog.Info(logName, fmt.Sprintf("覆盖模式清理完成，删除源中已不存在的条目 %d 条，组: %s", deleted, p.groupCode))
	return deleted > 0
}

// NotifyEngine 重建该组的匹配集并原子发布。
//
// 一次原子替换即让所有引用方生效，不需要给任何站点下发通道消息。
func (p *IPGroupProcessor) NotifyEngine(task model.BatchTask) {
	if p.groupCode == "" {
		return
	}
	waf_service.WafIPGroupServiceApp.RebuildGroupMatcher(p.groupCode)
}

// resolve 解析并校验目标 IP 组，结果缓存，多批次只解析一次。
func (p *IPGroupProcessor) resolve(task model.BatchTask, logName string) bool {
	if p.resolved {
		return p.groupCode != ""
	}
	p.resolved = true

	if task.BatchExtraConfig == "" {
		zlog.Error(logName, "未配置目标IP组(group_code)，任务终止 任务ID:"+task.Id)
		return false
	}
	var config IPGroupConfig
	if err := json.Unmarshal([]byte(task.BatchExtraConfig), &config); err != nil {
		zlog.Error(logName, "解析IP组配置失败: "+err.Error())
		return false
	}
	if config.GroupCode == "" {
		zlog.Error(logName, "未配置目标IP组(group_code)，任务终止 任务ID:"+task.Id)
		return false
	}

	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).Where("group_code = ?", config.GroupCode).Count(&cnt)
	if cnt == 0 {
		zlog.Error(logName, "目标IP组不存在，任务终止 组:"+config.GroupCode)
		return false
	}

	p.groupCode = config.GroupCode
	return true
}
