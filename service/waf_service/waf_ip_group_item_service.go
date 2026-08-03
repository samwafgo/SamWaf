package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"errors"
	"strings"
	"time"
)

type WafIPGroupItemService struct{}

var WafIPGroupItemServiceApp = new(WafIPGroupItemService)

// BatchAddResult 批量录入结果
type BatchAddResult struct {
	Success   int        `json:"success"`    //成功入库条数
	Skipped   int        `json:"skipped"`    //组内已存在被跳过
	Fail      int        `json:"fail"`       //格式非法条数
	FailLines []FailLine `json:"fail_lines"` //非法明细，最多返回前 50 条
	Total     int        `json:"total"`      //有效行总数（不含空行与注释行）
}

type FailLine struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

func (receiver *WafIPGroupItemService) AddApi(req request.WafIPGroupItemAddReq) error {
	ip := strings.TrimSpace(req.Ip)
	if err := validateGroupItemIP(ip); err != nil {
		return err
	}
	if err := receiver.checkGroupExists(req.GroupCode); err != nil {
		return err
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).Where("group_code = ? AND ip = ?", req.GroupCode, ip).Count(&cnt)
	if cnt > 0 {
		return errors.New("该IP已在组内: " + ip)
	}
	bean := newGroupItem(req.GroupCode, ip, req.Remarks)
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

func (receiver *WafIPGroupItemService) ModifyApi(req request.WafIPGroupItemEditReq) (string, error) {
	var bean model.IPGroupItem
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return "", errors.New("条目不存在")
	}
	ip := strings.TrimSpace(req.Ip)
	if err := validateGroupItemIP(ip); err != nil {
		return bean.GroupCode, err
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).
		Where("group_code = ? AND ip = ? AND id <> ?", bean.GroupCode, ip, req.Id).Count(&cnt)
	if cnt > 0 {
		return bean.GroupCode, errors.New("该IP已在组内: " + ip)
	}
	updateMap := map[string]interface{}{
		"ip":          ip,
		"remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.IPGroupItem{}).Where("id = ?", req.Id).Updates(updateMap).Error
	return bean.GroupCode, err
}

// BatchAddApi 多行文本批量录入。空行与 # 开头的注释行忽略；逐行校验，非法行不阻断其余行。
//
// 返回的 groupCode 供调用方在最后统一重建一次匹配集——不要逐行重建。
func (receiver *WafIPGroupItemService) BatchAddApi(req request.WafIPGroupItemBatchAddReq) (BatchAddResult, error) {
	result := BatchAddResult{FailLines: []FailLine{}}
	if err := receiver.checkGroupExists(req.GroupCode); err != nil {
		return result, err
	}

	// 组内已有条目，用于去重（同时挡住同一批文本里的重复行）
	var existRows []model.IPGroupItem
	global.GWAF_LOCAL_DB.Where("group_code = ?", req.GroupCode).Find(&existRows)
	exist := make(map[string]struct{}, len(existRows))
	for i := range existRows {
		exist[existRows[i].Ip] = struct{}{}
	}

	remark := req.Remarks
	if remark == "" {
		remark = time.Now().Format("20060102") + "批量添加"
	}

	pending := make([]*model.IPGroupItem, 0, 64)
	for idx, raw := range strings.Split(strings.ReplaceAll(req.Content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.Total++
		if err := validateGroupItemIP(line); err != nil {
			result.Fail++
			if len(result.FailLines) < 50 {
				result.FailLines = append(result.FailLines, FailLine{Line: idx + 1, Text: line, Reason: err.Error()})
			}
			continue
		}
		if _, dup := exist[line]; dup {
			result.Skipped++
			continue
		}
		exist[line] = struct{}{}
		pending = append(pending, newGroupItem(req.GroupCode, line, remark))
	}

	if len(pending) > 0 {
		if err := global.GWAF_LOCAL_DB.CreateInBatches(pending, 500).Error; err != nil {
			return result, err
		}
		result.Success = len(pending)
	}
	return result, nil
}

func (receiver *WafIPGroupItemService) GetDetailApi(req request.WafIPGroupItemDetailReq) model.IPGroupItem {
	var bean model.IPGroupItem
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

func (receiver *WafIPGroupItemService) GetListApi(req request.WafIPGroupItemSearchReq) ([]model.IPGroupItem, int64, error) {
	var list []model.IPGroupItem
	var total int64 = 0

	var whereField = " group_code = ? "
	var whereValues = []interface{}{req.GroupCode}
	if len(req.Ip) > 0 {
		whereField += " and ip like ? "
		whereValues = append(whereValues, "%"+req.Ip+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).Where(whereField, whereValues...).
		Order("CREATE_TIME desc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// DelApi 删除单条，返回所属组短码供调用方重建匹配集
func (receiver *WafIPGroupItemService) DelApi(req request.WafIPGroupItemDelReq) (string, error) {
	var bean model.IPGroupItem
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return "", err
	}
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.IPGroupItem{}).Error
	return bean.GroupCode, err
}

// BatchDelApi 批量删除，返回涉及的组短码列表（去重）
func (receiver *WafIPGroupItemService) BatchDelApi(req request.WafIPGroupItemBatchDelReq) ([]string, error) {
	if len(req.Ids) == 0 {
		return nil, errors.New("删除ID列表不能为空")
	}
	var codes []string
	if err := global.GWAF_LOCAL_DB.Model(&model.IPGroupItem{}).
		Where("id IN ?", req.Ids).Distinct("group_code").Pluck("group_code", &codes).Error; err != nil {
		return nil, err
	}
	err := global.GWAF_LOCAL_DB.Where("id IN ?", req.Ids).Delete(&model.IPGroupItem{}).Error
	return codes, err
}

// DelAllApi 清空某个组的全部条目
func (receiver *WafIPGroupItemService) DelAllApi(req request.WafIPGroupItemDelAllReq) error {
	if req.GroupCode == "" {
		return errors.New("组短码不能为空")
	}
	return global.GWAF_LOCAL_DB.Where("group_code = ?", req.GroupCode).Delete(&model.IPGroupItem{}).Error
}

func (receiver *WafIPGroupItemService) checkGroupExists(groupCode string) error {
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).Where("group_code = ?", groupCode).Count(&cnt)
	if cnt == 0 {
		return errors.New("IP组不存在: " + groupCode)
	}
	return nil
}

func newGroupItem(groupCode, ip, remarks string) *model.IPGroupItem {
	return &model.IPGroupItem{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		GroupCode: groupCode,
		Ip:        ip,
		Remarks:   remarks,
	}
}

// validateGroupItemIP 校验组内条目的 IP 模式。
// 全通配单独拦下：写进被白名单引用的组等于全站不设防，让用户改写成显式的 0.0.0.0/0。
func validateGroupItemIP(ip string) error {
	if ip == "" {
		return errors.New("IP不能为空")
	}
	if utils.IsCatchAllIPPattern(ip) {
		return errors.New("该写法会匹配所有IP，风险过高；如确需全匹配请显式填写 0.0.0.0/0 或 ::/0")
	}
	if ok, msg := utils.IsValidIPPattern(ip); !ok {
		return errors.New(msg)
	}
	return nil
}
