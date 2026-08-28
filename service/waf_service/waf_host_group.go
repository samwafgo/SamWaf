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

	"gorm.io/gorm"
)

type WafHostGroupService struct{}

var WafHostGroupServiceApp = new(WafHostGroupService)

const (
	hostGroupNameMaxLen    = 50
	hostGroupRemarksMaxLen = 200
	hostGroupAssignMaxSize = 500 //单次批量指派上限
)

// HostGroupOptions 下拉/左栏用的分组集合，额外带上「未分组」与「全部」的计数，
// 免得前端为了显示三个数字发三次请求。
type HostGroupOptions struct {
	List      []model.HostGroup `json:"list"`
	NoneCount int               `json:"none_count"` //未分组的网站数
	AllCount  int               `json:"all_count"`  //全部网站数（不含全局网站）
}

func (receiver *WafHostGroupService) AddApi(req request.WafHostGroupAddReq) (model.HostGroup, error) {
	name, err := normalizeGroupName(req.GroupName)
	if err != nil {
		return model.HostGroup{}, err
	}
	color, err := normalizeGroupColor(req.Color)
	if err != nil {
		return model.HostGroup{}, err
	}
	remarks, err := normalizeGroupRemarks(req.Remarks)
	if err != nil {
		return model.HostGroup{}, err
	}
	if err = receiver.checkNameFree(name, ""); err != nil {
		return model.HostGroup{}, err
	}

	var bean = &model.HostGroup{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		GroupName: name,
		// 分组短码固定由后端生成：它只是网站引用本组的内部键，用户无需关心
		GroupCode: uuid.GenUUID(),
		Color:     color,
		SortNo:    receiver.nextSortNo(),
		Remarks:   remarks,
	}
	if err = global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return model.HostGroup{}, err
	}
	return *bean, nil
}

// ModifyApi 只允许改名称、颜色与备注。分组短码创建后不可变——网站在引用它，
// 改码等于让组内所有网站悄悄变成「未知分组」。
func (receiver *WafHostGroupService) ModifyApi(req request.WafHostGroupEditReq) (model.HostGroup, error) {
	var bean model.HostGroup
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return model.HostGroup{}, errors.New("分组不存在")
	}
	name, err := normalizeGroupName(req.GroupName)
	if err != nil {
		return model.HostGroup{}, err
	}
	color, err := normalizeGroupColor(req.Color)
	if err != nil {
		return model.HostGroup{}, err
	}
	remarks, err := normalizeGroupRemarks(req.Remarks)
	if err != nil {
		return model.HostGroup{}, err
	}
	if err = receiver.checkNameFree(name, bean.Id); err != nil {
		return model.HostGroup{}, err
	}

	updateMap := map[string]interface{}{
		"group_name":  name,
		"color":       color,
		"remarks":     remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if err = global.GWAF_LOCAL_DB.Model(model.HostGroup{}).Where("id = ?", req.Id).Updates(updateMap).Error; err != nil {
		return model.HostGroup{}, err
	}
	bean.GroupName, bean.Color, bean.Remarks = name, color, remarks
	return bean, nil
}

// DelApi 删除分组。
//
// 组内网站不跟着删：先在同一事务里把它们的 group_code 清空（回落「未分组」），
// 再删组记录。两步必须同事务——中途失败会留下一批指向已删分组的网站。
// 返回被移出的网站数量，供前端提示。
func (receiver *WafHostGroupService) DelApi(req request.WafHostGroupDelReq) (int64, error) {
	var bean model.HostGroup
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return 0, errors.New("分组不存在")
	}
	var affected int64
	err := global.GWAF_LOCAL_DB.Transaction(func(tx *gorm.DB) error {
		ret := tx.Model(&model.Hosts{}).Where("group_code = ?", bean.GroupCode).
			Updates(map[string]interface{}{"group_code": "", "UPDATE_TIME": customtype.JsonTime(time.Now())})
		if ret.Error != nil {
			return ret.Error
		}
		affected = ret.RowsAffected
		return tx.Where("id = ?", req.Id).Delete(model.HostGroup{}).Error
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func (receiver *WafHostGroupService) GetDetailApi(req request.WafHostGroupDetailReq) model.HostGroup {
	var bean model.HostGroup
	global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Find(&bean)
	if bean.GroupCode != "" {
		list := []model.HostGroup{bean}
		receiver.fillHostCounts(list)
		bean = list[0]
	}
	return bean
}

func (receiver *WafHostGroupService) GetDetailByCodeApi(groupCode string) model.HostGroup {
	var bean model.HostGroup
	global.GWAF_LOCAL_DB.Where("group_code = ?", groupCode).Find(&bean)
	return bean
}

func (receiver *WafHostGroupService) GetListApi(req request.WafHostGroupSearchReq) ([]model.HostGroup, int64, error) {
	var list []model.HostGroup
	var total int64 = 0

	var whereField = " user_code = ? AND tenant_id = ? "
	var whereValues = []interface{}{global.GWAF_USER_CODE, global.GWAF_TENANT_ID}
	if len(req.GroupName) > 0 {
		whereField += " and group_name like ? "
		whereValues = append(whereValues, "%"+req.GroupName+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).Where(whereField, whereValues...).
		Order("sort_no asc, CREATE_TIME asc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).Where(whereField, whereValues...).Count(&total)

	receiver.fillHostCounts(list)
	return list, total, nil
}

// GetOptionsApi 返回全部分组（不分页）+ 未分组/全部的计数，供网站列表左栏与表单下拉使用
func (receiver *WafHostGroupService) GetOptionsApi() HostGroupOptions {
	list := make([]model.HostGroup, 0)
	global.GWAF_LOCAL_DB.Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Order("sort_no asc, CREATE_TIME asc").Find(&list)
	receiver.fillHostCounts(list)

	var noneCount, allCount int64
	// 全局网站不参与分组（它不是真实站点，只承载全局规则），计数里一并排除
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("global_host <> 1").Count(&allCount)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("global_host <> 1").
		Where("group_code = '' or group_code is null").Count(&noneCount)

	return HostGroupOptions{List: list, NoneCount: int(noneCount), AllCount: int(allCount)}
}

// SortApi 按 ids 数组下标批量写 sort_no，一次事务提交
func (receiver *WafHostGroupService) SortApi(req request.WafHostGroupSortReq) error {
	if len(req.Ids) == 0 {
		return errors.New("排序内容不能为空")
	}
	return global.GWAF_LOCAL_DB.Transaction(func(tx *gorm.DB) error {
		for i, id := range req.Ids {
			if err := tx.Model(model.HostGroup{}).Where("id = ?", id).
				Updates(map[string]interface{}{"sort_no": i, "UPDATE_TIME": customtype.JsonTime(time.Now())}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// AssignApi 批量把网站指派到某个分组，GroupCode 为空表示移出分组。
// 返回实际生效的网站数。
func (receiver *WafHostGroupService) AssignApi(req request.WafHostGroupAssignReq) (int64, error) {
	codes := make([]string, 0, len(req.HostCodes))
	seen := make(map[string]struct{}, len(req.HostCodes))
	for _, c := range req.HostCodes {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		codes = append(codes, c)
	}
	if len(codes) == 0 {
		return 0, errors.New("请选择要移动的网站")
	}
	if len(codes) > hostGroupAssignMaxSize {
		return 0, errors.New("单次最多移动 500 个网站")
	}

	groupCode := strings.TrimSpace(req.GroupCode)
	if groupCode != "" {
		var cnt int64
		global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).Where("group_code = ?", groupCode).Count(&cnt)
		if cnt == 0 {
			// 典型场景：前端页面停留期间别处把这个组删了
			return 0, errors.New("分组不存在")
		}
	}

	// 全局网站不参与分组：即使前端全选把它带上来，也在这里剔除，
	// 否则「该组 3 个站点」这句话会变成假的。剔除放在后端做，不依赖前端自觉。
	ret := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Where("code in ?", codes).Where("global_host <> 1").
		Updates(map[string]interface{}{"group_code": groupCode, "UPDATE_TIME": customtype.JsonTime(time.Now())})
	if ret.Error != nil {
		return 0, ret.Error
	}
	return ret.RowsAffected, nil
}

// fillHostCounts 一次聚合查询填充所有分组的网站数，避免逐组查询的 N+1
func (receiver *WafHostGroupService) fillHostCounts(list []model.HostGroup) {
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
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
		Select("group_code, count(*) as cnt").
		Where("group_code IN ?", codes).Where("global_host <> 1").
		Group("group_code").Scan(&rows)
	counts := make(map[string]int, len(rows))
	for _, r := range rows {
		counts[r.GroupCode] = r.Cnt
	}
	for i := range list {
		list[i].HostCount = counts[list[i].GroupCode]
	}
}

// checkNameFree 分组名在租户内唯一。excludeId 非空时排除自身（编辑场景）。
func (receiver *WafHostGroupService) checkNameFree(name, excludeId string) error {
	var cnt int64
	q := global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).
		Where("group_name = ? AND user_code = ? AND tenant_id = ?", name, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	if excludeId != "" {
		q = q.Where("id <> ?", excludeId)
	}
	if err := q.Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return errors.New("分组名称已存在: " + name)
	}
	return nil
}

// nextSortNo 新组排在最后
func (receiver *WafHostGroupService) nextSortNo() int {
	var maxNo *int
	global.GWAF_LOCAL_DB.Model(&model.HostGroup{}).
		Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Select("max(sort_no)").Scan(&maxNo)
	if maxNo == nil {
		return 0
	}
	return *maxNo + 1
}

func normalizeGroupName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("分组名称不能为空")
	}
	if len([]rune(name)) > hostGroupNameMaxLen {
		return "", errors.New("分组名称长度不能超过50")
	}
	return name, nil
}

func normalizeGroupColor(raw string) (string, error) {
	color := strings.TrimSpace(raw)
	if color == "" {
		return model.HostGroupColors[0], nil
	}
	if !model.IsValidHostGroupColor(color) {
		return "", errors.New("分组颜色不合法")
	}
	return color, nil
}

func normalizeGroupRemarks(raw string) (string, error) {
	remarks := strings.TrimSpace(raw)
	if len([]rune(remarks)) > hostGroupRemarksMaxLen {
		return "", errors.New("备注长度不能超过200")
	}
	return remarks, nil
}
