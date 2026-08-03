package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafenginecore/ipset"
	"errors"
	"strings"
	"time"
)

type WafIPGroupService struct{}

var WafIPGroupServiceApp = new(WafIPGroupService)

// IPGroupRefHost IP 组在某个站点上的引用情况
type IPGroupRefHost struct {
	HostCode string `json:"host_code"`
	HostName string `json:"host_name"`
	Block    int    `json:"block"` //该站点黑名单里引用了几条
	Allow    int    `json:"allow"` //该站点白名单里引用了几条
}

// IPGroupRefs IP 组的引用明细，删除确认弹窗用
type IPGroupRefs struct {
	GroupCode  string           `json:"group_code"`
	BlockCount int              `json:"block_count"`
	AllowCount int              `json:"allow_count"`
	Hosts      []IPGroupRefHost `json:"hosts"`
}

func (receiver *WafIPGroupService) AddApi(req request.WafIPGroupAddReq) (model.IPGroup, error) {
	name := strings.TrimSpace(req.GroupName)
	if name == "" {
		return model.IPGroup{}, errors.New("组名称不能为空")
	}
	// 组短码固定由后端生成：它只是黑白名单与规则引用本组的内部键，
	// 用户无需关心，也就不存在自定义带来的唯一性冲突。
	code := uuid.GenUUID()
	if err := receiver.checkNameCodeFree(name, code, ""); err != nil {
		return model.IPGroup{}, err
	}
	var bean = &model.IPGroup{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		GroupName: name,
		GroupCode: code,
		Remarks:   req.Remarks,
	}
	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return model.IPGroup{}, err
	}
	return *bean, nil
}

// ModifyApi 只允许改名称与备注。组短码创建后不可变——黑/白名单条目与自定义规则都在引用它，
// 改码等于让所有引用悄悄失效。
func (receiver *WafIPGroupService) ModifyApi(req request.WafIPGroupEditReq) (model.IPGroup, error) {
	var bean model.IPGroup
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return model.IPGroup{}, errors.New("IP组不存在")
	}
	name := strings.TrimSpace(req.GroupName)
	if name == "" {
		return model.IPGroup{}, errors.New("组名称不能为空")
	}
	if err := receiver.checkNameCodeFree(name, "", bean.Id); err != nil {
		return model.IPGroup{}, err
	}
	updateMap := map[string]interface{}{
		"group_name":  name,
		"remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(model.IPGroup{}).Where("id = ?", req.Id).Updates(updateMap).Error; err != nil {
		return model.IPGroup{}, err
	}
	bean.GroupName = name
	bean.Remarks = req.Remarks
	return bean, nil
}

// checkNameCodeFree 组名与组短码在租户内唯一。excludeId 非空时排除自身（编辑场景）。
func (receiver *WafIPGroupService) checkNameCodeFree(name, code, excludeId string) error {
	if name != "" {
		var cnt int64
		q := global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).
			Where("group_name = ? AND user_code = ? AND tenant_id = ?", name, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
		if excludeId != "" {
			q = q.Where("id <> ?", excludeId)
		}
		if err := q.Count(&cnt).Error; err != nil {
			return err
		}
		if cnt > 0 {
			return errors.New("组名称已存在: " + name)
		}
	}
	if code != "" {
		var cnt int64
		q := global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).
			Where("group_code = ? AND user_code = ? AND tenant_id = ?", code, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
		if excludeId != "" {
			q = q.Where("id <> ?", excludeId)
		}
		if err := q.Count(&cnt).Error; err != nil {
			return err
		}
		if cnt > 0 {
			return errors.New("组短码已存在: " + code)
		}
	}
	return nil
}

func (receiver *WafIPGroupService) GetDetailApi(req request.WafIPGroupDetailReq) model.IPGroup {
	var bean model.IPGroup
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	if bean.GroupCode != "" {
		bean.ItemCount = receiver.countItems(bean.GroupCode)
	}
	return bean
}

func (receiver *WafIPGroupService) GetDetailByCodeApi(groupCode string) model.IPGroup {
	var bean model.IPGroup
	global.GWAF_LOCAL_DB.Where("group_code=?", groupCode).Find(&bean)
	return bean
}

func (receiver *WafIPGroupService) GetListApi(req request.WafIPGroupSearchReq) ([]model.IPGroup, int64, error) {
	var list []model.IPGroup
	var total int64 = 0

	var whereField = " user_code = ? AND tenant_id = ? "
	var whereValues = []interface{}{global.GWAF_USER_CODE, global.GWAF_TENANT_ID}
	if len(req.GroupName) > 0 {
		whereField += " and group_name like ? "
		whereValues = append(whereValues, "%"+req.GroupName+"%")
	}
	if len(req.GroupCode) > 0 {
		whereField += " and group_code = ? "
		whereValues = append(whereValues, req.GroupCode)
	}

	global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).Where(whereField, whereValues...).
		Order("CREATE_TIME desc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).Where(whereField, whereValues...).Count(&total)

	receiver.fillItemCounts(list)
	return list, total, nil
}

// GetOptionsApi 返回全部 IP 组（不分页），供黑/白名单表单的下拉选择使用
func (receiver *WafIPGroupService) GetOptionsApi() []model.IPGroup {
	var list []model.IPGroup
	global.GWAF_LOCAL_DB.Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Order("group_name asc").Find(&list)
	receiver.fillItemCounts(list)
	return list
}

// fillItemCounts 一次聚合查询填充所有组的条目数，避免逐组查询的 N+1
func (receiver *WafIPGroupService) fillItemCounts(list []model.IPGroup) {
	if len(list) == 0 {
		return
	}
	codes := make([]string, 0, len(list))
	for i := range list {
		codes = append(codes, list[i].GroupCode)
	}
	type countRow struct {
		GroupCode string
		Cnt       int
	}
	var rows []countRow
	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).
		Select("group_code, count(*) as cnt").
		Where("group_code IN ?", codes).
		Group("group_code").Scan(&rows)
	counts := make(map[string]int, len(rows))
	for _, r := range rows {
		counts[r.GroupCode] = r.Cnt
	}
	for i := range list {
		list[i].ItemCount = counts[list[i].GroupCode]
	}
}

func (receiver *WafIPGroupService) countItems(groupCode string) int {
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).Where("group_code = ?", groupCode).Count(&cnt)
	return int(cnt)
}

// GetRefsApi 查询一个 IP 组被哪些黑/白名单条目引用、涉及哪些站点
func (receiver *WafIPGroupService) GetRefsApi(groupCode string) IPGroupRefs {
	refs := IPGroupRefs{GroupCode: groupCode, Hosts: []IPGroupRefHost{}}
	if groupCode == "" {
		return refs
	}
	var blockRows []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, groupCode).Find(&blockRows)
	var allowRows []model.IPAllowList
	global.GWAF_LOCAL_DB.Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, groupCode).Find(&allowRows)

	refs.BlockCount = len(blockRows)
	refs.AllowCount = len(allowRows)

	byHost := make(map[string]*IPGroupRefHost)
	order := make([]string, 0, 4)
	touch := func(hostCode string) *IPGroupRefHost {
		if h, ok := byHost[hostCode]; ok {
			return h
		}
		h := &IPGroupRefHost{HostCode: hostCode}
		byHost[hostCode] = h
		order = append(order, hostCode)
		return h
	}
	for _, r := range blockRows {
		touch(r.HostCode).Block++
	}
	for _, r := range allowRows {
		touch(r.HostCode).Allow++
	}
	// 补站点名称，方便前端在删除确认里展示「哪些站点会受影响」
	for _, code := range order {
		h := byHost[code]
		var host model.Hosts
		if err := global.GWAF_LOCAL_DB.Where("code = ?", code).First(&host).Error; err == nil {
			h.HostName = host.Host
		} else {
			h.HostName = code
		}
		refs.Hosts = append(refs.Hosts, *h)
	}
	return refs
}

// DelApi 删除 IP 组。返回受影响的站点编码列表，调用方需要据此刷新这些站点的内存名单。
//
// 默认拒绝删除被引用的组：级联会静默删掉引用它的白名单条目——运维会被自己的 WAF
// 挡在门外且无法撤销；黑名单侧则是瞬间放行。这类安全语义反转必须人眼确认，
// 所以要显式传 force=1。
//
// force 分支的执行顺序不能调整：
//  1. 先取受影响 host_code
//  2. 删黑/白名单引用行
//  3. 删组内条目、删组本体
//  4. 摘掉全局快照里的匹配集
//  5. 由调用方逐站点 NotifyWaf 去脏
//
// 第 4 步不能提到第 2 步之前：那会出现「引用行还在、匹配集已空」的窗口，
// 对白名单来说就是短暂失效导致误拦。反过来的中间态只是「按删除前的配置多生效几十毫秒」。
func (receiver *WafIPGroupService) DelApi(req request.WafIPGroupDelReq) ([]string, error) {
	var bean model.IPGroup
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return nil, errors.New("IP组不存在")
	}
	refs := receiver.GetRefsApi(bean.GroupCode)
	if (refs.BlockCount > 0 || refs.AllowCount > 0) && req.Force != 1 {
		return nil, errors.New("该IP组正被引用，无法直接删除")
	}

	affected := make([]string, 0, len(refs.Hosts))
	for _, h := range refs.Hosts {
		affected = append(affected, h.HostCode)
	}

	if refs.BlockCount > 0 {
		if err := global.GWAF_LOCAL_DB.Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, bean.GroupCode).
			Delete(&model.IPBlockList{}).Error; err != nil {
			return nil, err
		}
	}
	if refs.AllowCount > 0 {
		if err := global.GWAF_LOCAL_DB.Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, bean.GroupCode).
			Delete(&model.IPAllowList{}).Error; err != nil {
			return nil, err
		}
	}
	if err := global.GWAF_LOCAL_DB.Where("group_code = ?", bean.GroupCode).Delete(&model.IPGroupItem{}).Error; err != nil {
		return nil, err
	}
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.IPGroup{}).Error; err != nil {
		return nil, err
	}
	ipset.RemoveGroupMatcher(bean.GroupCode)
	return affected, nil
}

// ---------- 匹配集构建与发布 ----------

// RebuildGroupMatcher 重建单个组的匹配集并原子发布（COW）。
//
// 这是 IP 组「改一次、所有引用站点立即同步」的落点：无论多少站点引用该组，
// 这里只做一次原子指针替换，不给任何站点下发通道消息、不重建路由表。
// 组内条目增删改、组改名之后调用它即可。
func (receiver *WafIPGroupService) RebuildGroupMatcher(groupCode string) {
	if groupCode == "" {
		return
	}
	var group model.IPGroup
	if err := global.GWAF_LOCAL_DB.Where("group_code = ?", groupCode).First(&group).Error; err != nil {
		// 组已不存在（可能刚被删），摘掉快照即可
		ipset.RemoveGroupMatcher(groupCode)
		return
	}
	matcher, dropped := receiver.buildMatcher(groupCode)
	ipset.UpsertGroupMatcher(groupCode, group.GroupName, matcher)
	if dropped > 0 {
		zlog.Warn("IP组存在无法解析的条目已跳过", "group", group.GroupName, "code", groupCode, "dropped", dropped)
	}
}

// RebuildAllGroupMatchers 全量重建所有组的匹配集并整体发布。
// 启动时调用一次；单组重建失败或需要兜底时也可调用。
func (receiver *WafIPGroupService) RebuildAllGroupMatchers() {
	start := time.Now()
	var groups []model.IPGroup
	global.GWAF_LOCAL_DB.Find(&groups)

	snapshot := &ipset.GroupSnapshot{
		ByCode: make(map[string]*ipset.MatchSet, len(groups)),
		ByName: make(map[string]*ipset.MatchSet, len(groups)),
	}
	totalItems := 0
	totalDropped := 0
	for _, g := range groups {
		if g.GroupCode == "" {
			continue
		}
		matcher, dropped := receiver.buildMatcher(g.GroupCode)
		snapshot.ByCode[g.GroupCode] = matcher
		if g.GroupName != "" {
			// 名称重复时以先建的为准（Find 默认按插入顺序），并告警提示用户改名
			if _, dup := snapshot.ByName[g.GroupName]; dup {
				zlog.Warn("存在同名IP组，规则里按名称引用会命中先创建的那个，建议改名", "name", g.GroupName, "code", g.GroupCode)
			} else {
				snapshot.ByName[g.GroupName] = matcher
			}
		}
		totalItems += matcher.Len()
		totalDropped += dropped
	}
	ipset.SetGroupSnapshot(snapshot)
	zlog.Info("IP组匹配集已重建", "组数", len(snapshot.ByCode), "条目数", totalItems,
		"跳过的非法条目", totalDropped, "耗时", time.Since(start).String())
}

// buildMatcher 读取组内全部条目并编译成匹配集，返回 (匹配集, 被丢弃的非法条目数)。
func (receiver *WafIPGroupService) buildMatcher(groupCode string) (*ipset.MatchSet, int) {
	var items []model.IPGroupItem
	global.GWAF_LOCAL_DB.Where("group_code = ?", groupCode).Find(&items)
	ips := make([]string, 0, len(items))
	for i := range items {
		ips = append(ips, items[i].Ip)
	}
	m := ipset.BuildMatchSet(ips)
	if m.WildcardLen() > 512 {
		zlog.Warn("IP组内不连续掩码的通配符过多，每次未命中都要线性扫完，建议改用CIDR表达",
			"code", groupCode, "通配符条数", m.WildcardLen())
	}
	return m, m.Stats().Dropped
}

// GetHostCodesByGroup 返回引用了该组的所有站点编码（黑白名单合并去重），用于变更后刷新内存名单
func (receiver *WafIPGroupService) GetHostCodesByGroup(groupCode string) []string {
	if groupCode == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 4)
	collect := func(codes []string) {
		for _, c := range codes {
			if c == "" {
				continue
			}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	var blockHosts []string
	global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).
		Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, groupCode).
		Distinct("host_code").Pluck("host_code", &blockHosts)
	collect(blockHosts)

	var allowHosts []string
	global.GWAF_LOCAL_DB.Model(&model.IPAllowList{}).
		Where("ip_type = ? AND group_code = ?", model.IPEntryTypeGroup, groupCode).
		Distinct("host_code").Pluck("host_code", &allowHosts)
	collect(allowHosts)

	return out
}
